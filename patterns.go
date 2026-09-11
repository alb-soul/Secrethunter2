package main

import "regexp"

// Severity levels
const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"
	SevInfo     = "INFO"
)

// Pattern defines a secret/credential pattern to detect
type Pattern struct {
	Name       string
	Regex      *regexp.Regexp
	Severity   string
	MatchGroup int // 0 = full match, 1+ = capture group index
}

// patterns is the master list of all patterns to scan for.
// References: https://github.com/streaak/keyhacks + additional research.
var patterns = []Pattern{

	// ─── AWS ────────────────────────────────────────────────────────────────────
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`(?i)\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`),
		Severity: SevCritical,
	},
	{
		Name:       "AWS Secret Access Key",
		Regex:      regexp.MustCompile(`(?i)aws[_\-\.\s]*(?:secret[_\-\.\s]*)?(?:access[_\-\.\s]*)?key(?:[_\-\.\s]*id)?["\']?\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "AWS S3 Bucket URL",
		Regex:    regexp.MustCompile(`(?i)https?://[a-z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`),
		Severity: SevLow,
	},
	{
		Name:     "AWS STS / Assumed Role Token",
		Regex:    regexp.MustCompile(`(?i)\bFQoDYXdz[A-Za-z0-9/+=]{100,}`),
		Severity: SevCritical,
	},

	{
		Name:     "MinIO Access Key",
		Regex:    regexp.MustCompile(`\bminio[A-Za-z0-9]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "MinIO Secret Key",
		Regex:      regexp.MustCompile(`(?i)minio[_\-\s]*secret[_\-\s]*key["']?\s*[:=]\s*['"]?([A-Za-z0-9+/=]{40,})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},


	// ─── Private / Certificate Keys ─────────────────────────────────────────────
	{
		Name:     "RSA Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},
	{
		Name:     "EC Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},
	{
		Name:     "OpenSSH Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},
	{
		Name:     "PGP Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		Severity: SevCritical,
	},
	{
		Name:     "DSA Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},
	{
		Name:     "PKCS8 Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},
	{
		Name:     "Encrypted Private Key",
		Regex:    regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----[\\nrt"'\s]{0,40}[A-Za-z0-9+/]{40,}`),
		Severity: SevCritical,
	},

	// ─── Google ──────────────────────────────────────────────────────────────────
	{
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		Severity: SevHigh,
	},
	{
		Name:     "Google OAuth Access Token",
		Regex:    regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{100,200}`),
		Severity: SevCritical,
	},
	// Bare 6[...]{39} matches URL slugs, article IDs, etc. — require reCAPTCHA context
	{
		Name:       "Google reCAPTCHA Site Key",
		Regex:      regexp.MustCompile(`(?i)(?:recaptcha|site[_\-\s]*key|g-recaptcha|data-sitekey)["\']?\s*[=:]\s*['"]?(6[0-9A-Za-z_\-]{39})['"]?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:     "Google Cloud Service Account (type field)",
		Regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		Severity: SevCritical,
	},
	{
		Name:       "Google Cloud Private Key ID",
		Regex:      regexp.MustCompile(`"private_key_id"\s*:\s*"([a-f0-9]{40})"`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Firebase Cloud Messaging (FCM) Server Key",
		Regex:    regexp.MustCompile(`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`),
		Severity: SevHigh,
	},
	{
		Name:       "Firebase API Key / Config",
		Regex:      regexp.MustCompile(`(?i)firebase[A-Za-z]*(?:Config|apiKey|key)[\s]*[=:]\s*['"]?(AIza[0-9A-Za-z_\-]{35})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── GitHub ──────────────────────────────────────────────────────────────────
	{
		Name:     "GitHub Personal Access Token (ghp_)",
		Regex:    regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		Severity: SevCritical,
	},
	{
		Name:     "GitHub Fine-grained PAT",
		Regex:    regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
		Severity: SevCritical,
	},
	{
		Name:     "GitHub OAuth Access Token (gho_)",
		Regex:    regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
		Severity: SevCritical,
	},
	{
		Name:     "GitHub App User-to-Server Token (ghu_)",
		Regex:    regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`),
		Severity: SevHigh,
	},
	{
		Name:     "GitHub App Server-to-Server Token (ghs_)",
		Regex:    regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
		Severity: SevHigh,
	},
	{
		Name:     "GitHub App Refresh Token (ghr_)",
		Regex:    regexp.MustCompile(`ghr_[A-Za-z0-9]{76}`),
		Severity: SevHigh,
	},
	{
		Name:       "GitHub Client Secret",
		Regex:      regexp.MustCompile(`(?i)github[_\-\s]*client[_\-\s]*secret["\']?\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},

	// ─── GitLab ──────────────────────────────────────────────────────────────────
	{
		Name:     "GitLab Personal Access Token",
		Regex:    regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20}`),
		Severity: SevCritical,
	},
	{
		Name:     "GitLab Runner Registration Token",
		Regex:    regexp.MustCompile(`GR1348941[0-9A-Za-z_\-]{20}`),
		Severity: SevHigh,
	},
	{
		Name:     "GitLab CI/CD Job Token",
		Regex:    regexp.MustCompile(`glcbt-[0-9]{5}_[A-Za-z0-9_\-]{20}`),
		Severity: SevHigh,
	},
	{
		Name:     "GitLab Deploy Token",
		Regex:    regexp.MustCompile(`gldt-[0-9A-Za-z_\-]{20}`),
		Severity: SevHigh,
	},

	// ─── Stripe ──────────────────────────────────────────────────────────────────
	{
		Name:     "Stripe Live Secret Key",
		Regex:    regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,34}`),
		Severity: SevCritical,
	},
	{
		Name:     "Stripe Test Secret Key",
		Regex:    regexp.MustCompile(`sk_test_[0-9A-Za-z]{24,34}`),
		Severity: SevMedium,
	},
	{
		Name:     "Stripe Live Publishable Key",
		Regex:    regexp.MustCompile(`pk_live_[0-9A-Za-z]{24,34}`),
		Severity: SevMedium,
	},
	{
		Name:     "Stripe Restricted Key",
		Regex:    regexp.MustCompile(`rk_live_[0-9A-Za-z]{24,34}`),
		Severity: SevHigh,
	},
	{
		Name:     "Stripe Webhook Secret",
		Regex:    regexp.MustCompile(`whsec_[A-Za-z0-9]{32,64}`),
		Severity: SevHigh,
	},

	// ─── Slack ───────────────────────────────────────────────────────────────────
	{
		Name:     "Slack Webhook URL",
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Slack Bot Token (xoxb-)",
		Regex:    regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}`),
		Severity: SevCritical,
	},
	{
		Name:     "Slack User Token (xoxp-)",
		Regex:    regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}`),
		Severity: SevCritical,
	},
	{
		Name:     "Slack App-level Token (xapp-)",
		Regex:    regexp.MustCompile(`xapp-[0-9]-[A-Z0-9]{10,12}-[0-9]{13}-[A-Za-z0-9]{64,80}`),
		Severity: SevCritical,
	},
	{
		Name:     "Slack OAuth v2 Token (xoxe-)",
		Regex:    regexp.MustCompile(`xoxe\.[A-Za-z0-9\-]{150,}`),
		Severity: SevCritical,
	},

	// ─── SendGrid ────────────────────────────────────────────────────────────────
	{
		Name:     "SendGrid API Key",
		Regex:    regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		Severity: SevHigh,
	},

	// ─── Twilio ──────────────────────────────────────────────────────────────────
	{
		Name:     "Twilio Account SID",
		Regex:    regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "Twilio Auth Token",
		Regex:      regexp.MustCompile(`(?i)twilio[_\-\s]*auth[_\-\s]*token["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Twilio API Key SID",
		Regex:    regexp.MustCompile(`\bSK[a-f0-9]{32}\b`),
		Severity: SevHigh,
	},

	// ─── Mailgun ─────────────────────────────────────────────────────────────────
	{
		Name:     "Mailgun Private API Key",
		Regex:    regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Severity: SevHigh,
	},
	{
		Name:     "Mailgun Public API Key",
		Regex:    regexp.MustCompile(`pubkey-[0-9a-zA-Z]{32}`),
		Severity: SevMedium,
	},

	// ─── Mailchimp ───────────────────────────────────────────────────────────────
	{
		Name:     "Mailchimp API Key",
		Regex:    regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
		Severity: SevHigh,
	},

	// ─── Square ──────────────────────────────────────────────────────────────────
	// Note: require a non-base64 char before EAAA to avoid matching base64 data URIs
	// (base64 streams only use A-Za-z0-9+/= so a real token must be preceded by ", ', :, space, etc.)
	{
		Name:       "Square Access Token",
		Regex:      regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])(EAAA[a-zA-Z0-9]{56,80})`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Square App ID / Client Secret",
		Regex:    regexp.MustCompile(`sq0[a-z]{3}-[0-9A-Za-z_\-]{22,43}`),
		Severity: SevMedium,
	},
	{
		Name:       "Square Sandbox Token",
		Regex:      regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])(EAAAB[a-zA-Z0-9]{54,78})`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── PayPal / Braintree ───────────────────────────────────────────────────────
	{
		Name:     "PayPal / Braintree Access Token",
		Regex:    regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
		Severity: SevCritical,
	},
	{
		Name:       "PayPal Client ID/Secret (context)",
		Regex:      regexp.MustCompile(`(?i)paypal[_\-\s]*(?:client[_\-\s]*)?(?:id|secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{15,80})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Razorpay ─────────────────────────────────────────────────────────────────
	{
		Name:     "Razorpay Live Key",
		Regex:    regexp.MustCompile(`rzp_live_[A-Za-z0-9]{14}`),
		Severity: SevCritical,
	},
	{
		Name:     "Razorpay Test Key",
		Regex:    regexp.MustCompile(`rzp_test_[A-Za-z0-9]{14}`),
		Severity: SevMedium,
	},

	// ─── Shopify ──────────────────────────────────────────────────────────────────
	{
		Name:     "Shopify Admin API Access Token",
		Regex:    regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Severity: SevCritical,
	},
	{
		Name:     "Shopify Partner API Token",
		Regex:    regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`),
		Severity: SevHigh,
	},
	{
		Name:     "Shopify Custom App Token",
		Regex:    regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`),
		Severity: SevHigh,
	},
	{
		Name:     "Shopify Shared Secret",
		Regex:    regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		Severity: SevHigh,
	},

	// ─── Mapbox ──────────────────────────────────────────────────────────────────
	{
		Name:     "Mapbox Secret Token",
		Regex:    regexp.MustCompile(`sk\.[A-Za-z0-9_\-]{60}\.[A-Za-z0-9]{22}`),
		Severity: SevCritical,
	},
	{
		Name:     "Mapbox Public Token",
		Regex:    regexp.MustCompile(`pk\.[A-Za-z0-9_\-]{60}\.[A-Za-z0-9]{22}`),
		Severity: SevMedium,
	},
	{
		Name:     "Mapbox Temporary Token",
		Regex:    regexp.MustCompile(`tk\.[A-Za-z0-9_\-]{60}\.[A-Za-z0-9]{22}`),
		Severity: SevMedium,
	},

	// ─── Heroku ──────────────────────────────────────────────────────────────────
	{
		Name:       "Heroku API Key",
		Regex:      regexp.MustCompile(`(?i)heroku[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── HubSpot ─────────────────────────────────────────────────────────────────
	{
		Name:       "HubSpot API Key (hapikey)",
		Regex:      regexp.MustCompile(`(?i)hapikey["\']?\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "HubSpot Private App Token",
		Regex:    regexp.MustCompile(`pat-[a-z]{2}[0-9]-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: SevHigh,
	},

	// ─── Telegram ────────────────────────────────────────────────────────────────
	{
		Name:     "Telegram Bot API Token",
		Regex:    regexp.MustCompile(`[0-9]{8,10}:[0-9A-Za-z_\-]{35}`),
		Severity: SevHigh,
	},

	// ─── Discord ─────────────────────────────────────────────────────────────────
	{
		Name:     "Discord Webhook URL",
		Regex:    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}`),
		Severity: SevHigh,
	},
	{
		Name:     "Discord Bot Token",
		Regex:    regexp.MustCompile(`[MN][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}`),
		Severity: SevCritical,
	},
	{
		Name:       "Discord Client Secret",
		Regex:      regexp.MustCompile(`(?i)discord[_\-\s]*(?:client[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Microsoft / Azure ────────────────────────────────────────────────────────
	{
		Name:     "Microsoft Teams Webhook",
		Regex:    regexp.MustCompile(`https://[a-zA-Z0-9\-]+\.webhook\.office\.com/webhookb2/[0-9a-f\-]{36}@[0-9a-f\-]{36}/IncomingWebhook/[0-9a-f]{32}/[0-9a-f\-]{36}`),
		Severity: SevHigh,
	},
	{
		Name:       "Azure Storage Account Key",
		Regex:      regexp.MustCompile(`(?i)(?:accountkey|storagekey|account[_\-\s]*key)["\']?\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Azure Client Secret",
		Regex:      regexp.MustCompile(`(?i)(?:client[_\-\s]*secret|clientsecret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_~\-\.]{34,44})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Azure SAS Token",
		Regex:    regexp.MustCompile(`sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&(?:s[a-z]=(?:[a-z]+)&)*sig=[A-Za-z0-9%+/]{43,44}(?:%3D|=)?`),
		Severity: SevHigh,
	},
	{
		Name:       "Azure Connection String",
		Regex:      regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==`),
		Severity:   SevCritical,
	},

	// ─── AI / ML APIs ─────────────────────────────────────────────────────────────
	{
		// Old OpenAI format: sk-[20chars]T3BlbkFJ[20chars]
		Name:     "OpenAI API Key (legacy)",
		Regex:    regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
		Severity: SevCritical,
	},
	{
		// New project-scoped key
		Name:     "OpenAI API Key (project)",
		Regex:    regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{100,200}`),
		Severity: SevCritical,
	},
	{
		// Service account key format
		Name:     "OpenAI Service Account Key",
		Regex:    regexp.MustCompile(`sk-svcacct-[A-Za-z0-9_\-]{100,200}`),
		Severity: SevCritical,
	},
	{
		Name:     "Anthropic API Key",
		Regex:    regexp.MustCompile(`sk-ant-api0[3-9]-[A-Za-z0-9_\-]{93,110}`),
		Severity: SevCritical,
	},
	{
		Name:     "Replicate API Token",
		Regex:    regexp.MustCompile(`r8_[A-Za-z0-9]{37}`),
		Severity: SevHigh,
	},
	{
		Name:     "Hugging Face Access Token",
		Regex:    regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`),
		Severity: SevHigh,
	},
	// Cohere keys have no distinctive prefix — require "cohere" context to avoid
	// matching any 40-char alphanumeric string (base64, hashes, function names, etc.)
	{
		Name:       "Cohere API Key",
		Regex:      regexp.MustCompile(`(?i)cohere[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Analytics / Monitoring ──────────────────────────────────────────────────
	{
		Name:       "Algolia API Key",
		Regex:      regexp.MustCompile(`(?i)(?:algolia|x-algolia)[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Algolia Application ID",
		Regex:      regexp.MustCompile(`(?i)(?:algolia|x-algolia)[_\-\s]*(?:app(?:lication)?[_\-\s]*)?id["\']?\s*[=:]\s*['"]?([A-Z0-9]{10})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "DataDog API Key",
		Regex:      regexp.MustCompile(`(?i)datadog[_\-\s]*api[_\-\s]*key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// NRAK- = User API Key (Personal API Key) — confirmed community + keyhacks
	// Used for NerdGraph (GraphQL) and REST API v2
	{
		Name:     "New Relic User API Key (NRAK-)",
		Regex:    regexp.MustCompile(`NRAK-[A-Z0-9]{27}`),
		Severity: SevHigh,
	},
	// License key = 40-char hex, no distinctive prefix — use context-based match
	// Official docs: "40-character hexadecimal string associated with a New Relic account"
	{
		Name:       "New Relic License Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:new[_\-\s]*relic[_\-\s]*)?license[_\-\s]*key["\']?\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// NRII prefix not confirmed by official docs or keyhacks — use context-based
	{
		Name:       "New Relic Ingest / Insert Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:new[_\-\s]*relic[_\-\s]*)?(?:ingest|insert)[_\-\s]*key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32,50})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// NRIQ (no dash) confirmed by real-world finding: NRIQRbGp5pAFA5sfIFpUcyYgEksx6QN26MsRQ4NcjzGS
	// Used with X-Query-Key header on insights-api.newrelic.com
	{
		Name:     "New Relic Insights Query Key (NRIQ)",
		Regex:    regexp.MustCompile(`NRIQ[A-Za-z0-9]{40}`),
		Severity: SevMedium,
	},
	{
		Name:     "Sentry DSN",
		Regex:    regexp.MustCompile(`https://[0-9a-f]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+`),
		Severity: SevMedium,
	},
	{
		Name:       "Amplitude API Key",
		Regex:      regexp.MustCompile(`(?i)amplitude[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	// Secret Key untuk Dashboard REST / Export / User Privacy API
	// (basic auth api_key:secret_key) — INI yang sensitif, bukan API Key ingest.
	{
		Name:       "Amplitude Secret Key (Export/REST, context)",
		Regex:      regexp.MustCompile(`(?i)amplitude[^"\n]{0,60}?(?:secret|export)[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([A-Za-z0-9+/=_-]{24,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Dynatrace Token",
		Regex:    regexp.MustCompile(`dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}`),
		Severity: SevHigh,
	},
	{
		Name:     "Grafana API Key",
		Regex:    regexp.MustCompile(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`),
		Severity: SevHigh,
	},
	{
		Name:       "Grafana API Key (legacy basic auth context)",
		Regex:      regexp.MustCompile(`(?i)grafana[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,80})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── PubNub ──────────────────────────────────────────────────────────────────
	{
		Name:     "PubNub Subscribe Key",
		Regex:    regexp.MustCompile(`sub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: SevMedium,
	},
	{
		Name:     "PubNub Publish Key",
		Regex:    regexp.MustCompile(`pub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: SevHigh,
	},
	// PubNub Secret Key = "sec-c-" + base64(UUID) — official format is 44–48 base64
	// chars (e.g. sec-c-OTYxNTQ2NjctNzAzMi00YzQxLWExMGItMGQ0YTgxM2VlMzc3 decodes to a
	// UUID). Charset is standard base64 (no dashes), so this won't match dashed
	// CSS class names like "sec-c-main-header-...". Full admin / PAM access → CRITICAL.
	{
		Name:     "PubNub Secret Key (sec-c-)",
		Regex:    regexp.MustCompile(`\bsec-c-[A-Za-z0-9+/]{40,52}`),
		Severity: SevCritical,
	},
	{
		Name:       "PubNub Secret Key",
		Regex:      regexp.MustCompile(`(?i)pubnub[_\-\s]*(?:secret[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{36,64})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},

	// ─── Dropbox ─────────────────────────────────────────────────────────────────
	{
		Name:     "Dropbox Long-lived Token",
		Regex:    regexp.MustCompile(`sl\.[A-Za-z0-9_\-]{135,140}`),
		Severity: SevHigh,
	},
	{
		Name:       "Dropbox App Key/Secret (context)",
		Regex:      regexp.MustCompile(`(?i)dropbox[_\-\s]*(?:app[_\-\s]*)?(?:key|secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{15,20})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── NPM ─────────────────────────────────────────────────────────────────────
	{
		Name:     "NPM Access Token",
		Regex:    regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Severity: SevHigh,
	},
	{
		Name:     "NPM Auth Token (_authToken)",
		Regex:    regexp.MustCompile(`//registry\.npmjs\.org/:_authToken\s*=\s*([A-Za-z0-9_\-]{36,})`),
		Severity: SevHigh,
	},

	// ─── Social Media ────────────────────────────────────────────────────────────
	{
		Name:     "Facebook / Meta Access Token",
		Regex:    regexp.MustCompile(`\bEAA[A-Za-z0-9]{50,}`),
		Severity: SevHigh,
	},
	{
		Name:       "Facebook App Secret",
		Regex:      regexp.MustCompile(`(?i)(?:fb|facebook)[_\-\s]*(?:app[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	// Twitter Bearer tokens always start with AAAA but so do base64-encoded null runs.
	// Require a non-base64 char before AAAA (same fix as Square) to block false positives
	// from data:image/png;base64,... streams.
	{
		Name:       "Twitter/X Bearer Token",
		Regex:      regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])(AAAA[A-Za-z0-9%]{100,})`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Twitter/X API Secret",
		Regex:      regexp.MustCompile(`(?i)twitter[_\-\s]*(?:api[_\-\s]*)?(?:secret|consumer[_\-\s]*secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{50})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Instagram Graph API Token (EAAJj...)",
		Regex:    regexp.MustCompile(`EAAJj[A-Za-z0-9]+`),
		Severity: SevHigh,
	},
	// ─── CI/CD ────────────────────────────────────────────────────────────────────
	{
		Name:       "CircleCI Personal API Token",
		Regex:      regexp.MustCompile(`(?i)circle[_\-\s]*(?:ci[_\-\s]*)?(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Travis CI API Token",
		Regex:      regexp.MustCompile(`(?i)travis[_\-\s]*(?:ci[_\-\s]*)?(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{22,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Buildkite API Token",
		Regex:      regexp.MustCompile(`(?i)buildkite[_\-\s]*(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9\-_]{20,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "SonarQube User Token",
		Regex:    regexp.MustCompile(`squ_[0-9a-f]{40}`),
		Severity: SevHigh,
	},
	{
		Name:     "SonarQube Project Analysis Token",
		Regex:    regexp.MustCompile(`sqp_[0-9a-f]{40}`),
		Severity: SevHigh,
	},
	{
		Name:     "SonarCloud Token",
		Regex:    regexp.MustCompile(`sqa_[0-9a-f]{40}`),
		Severity: SevHigh,
	},

	// ─── Project Management / Collaboration ──────────────────────────────────────
	{
		Name:     "Linear API Key",
		Regex:    regexp.MustCompile(`lin_api_[A-Za-z0-9]{40}`),
		Severity: SevHigh,
	},
	{
		Name:     "Notion Integration Token",
		Regex:    regexp.MustCompile(`secret_[A-Za-z0-9]{43}`),
		Severity: SevHigh,
	},
	{
		Name:     "Notion Internal Integration Token (ntn_)",
		Regex:    regexp.MustCompile(`ntn_[A-Za-z0-9]{50}`),
		Severity: SevHigh,
	},
	{
		Name:     "Asana Personal Access Token",
		Regex:    regexp.MustCompile(`\d/[A-Za-z0-9]{18}:[a-f0-9]{32}`),
		Severity: SevHigh,
	},
	{
		Name:       "Asana PAT (context)",
		Regex:      regexp.MustCompile(`(?i)asana[_\-\s]*(?:(?:personal[_\-\s]*)?access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9/]{40,80})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "PagerDuty API Token",
		Regex:      regexp.MustCompile(`(?i)pagerduty[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Airtable Personal Access Token",
		Regex:    regexp.MustCompile(`pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`),
		Severity: SevHigh,
	},
	{
		Name:     "Airtable API Key (legacy)",
		Regex:    regexp.MustCompile(`(?i)airtable[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?(key[A-Za-z0-9]{14})['"]?`),
		Severity: SevMedium,
		MatchGroup: 1,
	},
	{
		Name:     "Zapier Webhook URL",
		Regex:    regexp.MustCompile(`https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+`),
		Severity: SevMedium,
	},

	// ─── Infrastructure / DevOps ──────────────────────────────────────────────────
	{
		Name:     "DigitalOcean Personal Access Token",
		Regex:    regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		Severity: SevCritical,
	},
	{
		Name:     "DigitalOcean OAuth Token",
		Regex:    regexp.MustCompile(`doo_v1_[a-f0-9]{64}`),
		Severity: SevCritical,
	},
	{
		Name:     "DigitalOcean Refresh Token",
		Regex:    regexp.MustCompile(`dor_v1_[a-f0-9]{64}`),
		Severity: SevHigh,
	},
	{
		Name:     "Cloudflare API Token",
		Regex:    regexp.MustCompile(`(?i)(?:cf|cloudflare)[_\-\s]*(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40})['"]?`),
		Severity: SevCritical,
		MatchGroup: 1,
	},
	{
		Name:       "Cloudflare Global API Key",
		Regex:      regexp.MustCompile(`(?i)cloudflare[_\-\s]*(?:global[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{37})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Infura Project ID / Secret",
		Regex:    regexp.MustCompile(`(?i)infura[_\-\s]*(?:project[_\-\s]*)?(?:id|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity: SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Cloudinary URL",
		Regex:    regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+`),
		Severity: SevHigh,
	},

	// ─── Database Connection Strings ─────────────────────────────────────────────
	{
		Name:     "MongoDB URI",
		Regex:    regexp.MustCompile(`mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-@./%]+`),
		Severity: SevCritical,
	},
	{
		Name:     "PostgreSQL URI",
		Regex:    regexp.MustCompile(`postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s]+@[A-Za-z0-9_\-.]+(?::[0-9]+)?/[A-Za-z0-9_\-]+`),
		Severity: SevCritical,
	},
	{
		Name:     "MySQL URI",
		Regex:    regexp.MustCompile(`mysql(?:2)?://[A-Za-z0-9_\-]+:[^@\s]+@[A-Za-z0-9_\-.]+(?::[0-9]+)?/[A-Za-z0-9_\-]+`),
		Severity: SevCritical,
	},
	{
		Name:     "Redis URI with password",
		Regex:    regexp.MustCompile(`rediss?://:[^@\s]+@[A-Za-z0-9_\-.]+(?::[0-9]+)?`),
		Severity: SevCritical,
	},
	{
		Name:     "SMTP / SMTPS URI",
		Regex:    regexp.MustCompile(`smtps?://[A-Za-z0-9_%\-]+:[^@\s]+@[A-Za-z0-9_\-.]+(?::[0-9]+)?`),
		Severity: SevCritical,
	},

	// ─── JWT ─────────────────────────────────────────────────────────────────────
	{
		Name:     "JSON Web Token (JWT)",
		Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}`),
		Severity: SevMedium,
	},

	// ─── Salesforce ──────────────────────────────────────────────────────────────
	{
		Name:     "Salesforce Access Token",
		Regex:    regexp.MustCompile(`00D[A-Za-z0-9]{15}![A-Za-z0-9_.]{80,100}`),
		Severity: SevCritical,
	},

	// ─── Twitch ───────────────────────────────────────────────────────────────────
	{
		Name:       "Twitch Client Secret",
		Regex:      regexp.MustCompile(`(?i)twitch[_\-\s]*(?:client[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([a-z0-9]{30})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Twitch OAuth Token",
		Regex:    regexp.MustCompile(`oauth:[A-Za-z0-9]{30}`),
		Severity: SevHigh,
	},

	// ─── Auth0 ───────────────────────────────────────────────────────────────────
	{
		Name:       "Auth0 Client Secret",
		Regex:      regexp.MustCompile(`(?i)auth0[_\-\s]*(?:client[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{64})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Auth0 Domain",
		Regex:    regexp.MustCompile(`[a-zA-Z0-9_\-]+\.auth0\.com`),
		Severity: SevLow,
	},

	// ─── Okta ────────────────────────────────────────────────────────────────────
	{
		Name:       "Okta API Token",
		Regex:      regexp.MustCompile(`(?i)okta[_\-\s]*(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([0-9A-Za-z]{40,42})['"]?`),
		Severity:   SevCritical,
		MatchGroup: 1,
	},
	{
		Name:     "Okta Domain",
		Regex:    regexp.MustCompile(`[a-zA-Z0-9_\-]+\.okta(?:preview)?\.com`),
		Severity: SevLow,
	},

	// ─── Spotify ─────────────────────────────────────────────────────────────────
	{
		Name:       "Spotify Client ID/Secret (context)",
		Regex:      regexp.MustCompile(`(?i)spotify[_\-\s]*(?:client[_\-\s]*)?(?:id|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Zendesk ─────────────────────────────────────────────────────────────────
	{
		Name:       "Zendesk API Token",
		Regex:      regexp.MustCompile(`(?i)zendesk[_\-\s]*(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Shodan ──────────────────────────────────────────────────────────────────
	{
		Name:       "Shodan API Key",
		Regex:      regexp.MustCompile(`(?i)shodan[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── WakaTime ────────────────────────────────────────────────────────────────
	{
		Name:       "WakaTime API Key",
		Regex:      regexp.MustCompile(`(?i)wakatime[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── BrowserStack ────────────────────────────────────────────────────────────
	{
		Name:       "BrowserStack Access Key",
		Regex:      regexp.MustCompile(`(?i)browserstack[_\-\s]*(?:access[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Contentful ──────────────────────────────────────────────────────────────
	{
		Name:       "Contentful Access Token",
		Regex:      regexp.MustCompile(`(?i)contentful[_\-\s]*(?:access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{43})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Contentful Space ID",
		Regex:      regexp.MustCompile(`(?i)contentful[_\-\s]*space[_\-\s]*id["\']?\s*[=:]\s*['"]?([a-z0-9]{18})['"]?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},

	// ─── Algolia Extra ───────────────────────────────────────────────────────────
	{
		Name:       "Algolia Search-Only API Key",
		Regex:      regexp.MustCompile(`(?i)algolia[_\-\s]*search[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Bit.ly ──────────────────────────────────────────────────────────────────
	{
		Name:       "Bit.ly Access Token",
		Regex:      regexp.MustCompile(`(?i)bitly[_\-\s]*(?:access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,50})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Intercom ────────────────────────────────────────────────────────────────
	{
		Name:       "Intercom Access Token",
		Regex:      regexp.MustCompile(`(?i)intercom[_\-\s]*(?:access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{60})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Supabase ────────────────────────────────────────────────────────────────
	{
		Name:     "Supabase Service Role Key",
		Regex:    regexp.MustCompile(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJyb2xlIjoic2VydmljZV9yb2xlIi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
		Severity: SevCritical,
	},
	{
		Name:       "Supabase Anon/Public Key (context)",
		Regex:      regexp.MustCompile(`(?i)supabase[_\-\s]*(?:anon|public|service[_\-\s]*role)[_\-\s]*(?:key|token)["\']?\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},

	// ─── Vercel ──────────────────────────────────────────────────────────────────
	{
		Name:     "Vercel Access Token",
		Regex:    regexp.MustCompile(`(?i)vercel[_\-\s]*(?:access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{24})['"]?`),
		Severity: SevHigh,
		MatchGroup: 1,
	},

	// ─── Keygen ──────────────────────────────────────────────────────────────────
	{
		Name:       "Keygen API Token",
		Regex:      regexp.MustCompile(`(?i)keygen[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9\-]{32,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Freshdesk ───────────────────────────────────────────────────────────────
	{
		Name:       "FreshDesk API Key",
		Regex:      regexp.MustCompile(`(?i)freshdesk[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Iterable ────────────────────────────────────────────────────────────────
	{
		Name:       "Iterable API Key",
		Regex:      regexp.MustCompile(`(?i)iterable[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{30,50})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Keen.io ─────────────────────────────────────────────────────────────────
	{
		Name:       "Keen.io API Key",
		Regex:      regexp.MustCompile(`(?i)keen[_\-\s]*(?:io[_\-\s]*)?(?:(?:read|write|master)[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32,80})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Lokalise ────────────────────────────────────────────────────────────────
	{
		Name:       "Lokalise API Key",
		Regex:      regexp.MustCompile(`(?i)lokalise[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Cypress ─────────────────────────────────────────────────────────────────
	{
		Name:       "Cypress Record Key",
		Regex:      regexp.MustCompile(`(?i)cypress[_\-\s]*(?:record[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── WeGlot ──────────────────────────────────────────────────────────────────
	// Weglot API keys always start with "wg_" followed by ~32 alphanumeric chars
	// This direct prefix match catches keys even without "weglot" keyword context
	{
		Name:     "Weglot API Key",
		Regex:    regexp.MustCompile(`\bwg_[A-Za-z0-9]{28,40}\b`),
		Severity: SevMedium,
	},
	// Fallback: context-based match if key doesn't have wg_ prefix (older format)
	{
		Name:       "Weglot API Key (context)",
		Regex:      regexp.MustCompile(`(?i)weglot[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{30,50})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Pendo ───────────────────────────────────────────────────────────────────
	{
		Name:       "Pendo Integration Key",
		Regex:      regexp.MustCompile(`(?i)(?:pendo[_\-\s]*)(?:integration[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Delighted ────────────────────────────────────────────────────────────────
	{
		Name:       "Delighted API Key",
		Regex:      regexp.MustCompile(`(?i)delighted[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{30,50})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── WPEngine ────────────────────────────────────────────────────────────────
	{
		Name:       "WPEngine API Key",
		Regex:      regexp.MustCompile(`(?i)(?:wpe|wpengine)[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{30,50})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Ipstack ─────────────────────────────────────────────────────────────────
	{
		Name:       "Ipstack API Key",
		Regex:      regexp.MustCompile(`(?i)ipstack[_\-\s]*(?:api[_\-\s]*)?(?:key|access[_\-\s]*key)["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},

	// ─── ButterCMS ───────────────────────────────────────────────────────────────
	{
		Name:       "ButterCMS API Key",
		Regex:      regexp.MustCompile(`(?i)butter[_\-\s]*(?:cms[_\-\s]*)?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40,50})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── JumpCloud ────────────────────────────────────────────────────────────────
	{
		Name:       "JumpCloud API Key",
		Regex:      regexp.MustCompile(`(?i)jumpcloud[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Loqate ──────────────────────────────────────────────────────────────────
	{
		Name:       "Loqate API Key",
		Regex:      regexp.MustCompile(`(?i)loqate[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Bing Maps ───────────────────────────────────────────────────────────────
	{
		Name:       "Bing Maps API Key",
		Regex:      regexp.MustCompile(`(?i)bing[_\-\s]*(?:maps[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{64,84})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Calendly ────────────────────────────────────────────────────────────────
	{
		Name:       "Calendly API Key",
		Regex:      regexp.MustCompile(`(?i)calendly[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,80})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── LinkedIn ─────────────────────────────────────────────────────────────────
	{
		Name:       "LinkedIn Client ID/Secret",
		Regex:      regexp.MustCompile(`(?i)linkedin[_\-\s]*(?:client[_\-\s]*)?(?:id|secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{12,20})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── OpsGenie ─────────────────────────────────────────────────────────────────
	{
		Name:       "OpsGenie API Key",
		Regex:      regexp.MustCompile(`(?i)(?:opsgenie|genie)[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Visual Studio App Center ─────────────────────────────────────────────────
	{
		Name:       "VS App Center / AppCenter API Token",
		Regex:      regexp.MustCompile(`(?i)app[_\-\s]*center[_\-\s]*(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Fa-f0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Pivotal Tracker ──────────────────────────────────────────────────────────
	{
		Name:       "PivotalTracker API Token",
		Regex:      regexp.MustCompile(`(?i)pivotal[_\-\s]*(?:tracker[_\-\s]*)?(?:api[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Deviant Art ─────────────────────────────────────────────────────────────
	{
		Name:       "DeviantArt Client Secret",
		Regex:      regexp.MustCompile(`(?i)deviantart[_\-\s]*(?:client[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── SauceLabs ───────────────────────────────────────────────────────────────
	{
		Name:       "SauceLabs Access Key",
		Regex:      regexp.MustCompile(`(?i)saucelabs[_\-\s]*(?:access[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9\-]{36})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES (verified against official docs / GitGuardian, 2025–2026)
	// Two classes:
	//   (A) Context-free  — token has a unique prefix, no surrounding keyword needed
	//   (B) Context-based — no distinctive prefix, requires a service keyword nearby
	// ════════════════════════════════════════════════════════════════════════════

	// ─── Supabase (new opaque keys, GA 2025) ────────────────────────────────────
	{
		Name:     "Supabase Publishable Key (sb_publishable_)",
		Regex:    regexp.MustCompile(`\bsb_publishable_[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "Supabase Secret Key (sb_secret_)",
		Regex:    regexp.MustCompile(`\bsb_secret_[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevCritical,
	},

	// ─── Clerk ──────────────────────────────────────────────────────────────────
	// NOTE: pk_/sk_(live|test)_ prefixes OVERLAP Stripe. Per design we report both;
	// Stripe patterns appear earlier so a value in Stripe's 24–34 length range is
	// labelled Stripe (dedup keeps one finding per value). Clerk keys are usually
	// longer (base64 FAPI URL), so these catch the Clerk-only cases.
	{
		Name:     "Clerk Secret Key (sk_live_)",
		Regex:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{35,}\b`),
		Severity: SevCritical,
	},
	{
		Name:     "Clerk Secret Key (sk_test_)",
		Regex:    regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{35,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "Clerk Publishable Key (pk_live_/pk_test_)",
		Regex:    regexp.MustCompile(`\bpk_(?:live|test)_[A-Za-z0-9]{35,}\b`),
		Severity: SevMedium,
	},

	// ─── PlanetScale ────────────────────────────────────────────────────────────
	{
		Name:     "PlanetScale Service Token (pscale_tkn_)",
		Regex:    regexp.MustCompile(`\bpscale_tkn_[A-Za-z0-9_\-]{32,}`),
		Severity: SevCritical,
	},
	{
		Name:     "PlanetScale DB Password (pscale_pw_)",
		Regex:    regexp.MustCompile(`\bpscale_pw_[A-Za-z0-9_\-]{32,}`),
		Severity: SevCritical,
	},
	{
		Name:     "PlanetScale OAuth Token (pscale_oauth_)",
		Regex:    regexp.MustCompile(`\bpscale_oauth_[A-Za-z0-9_\-]{32,}`),
		Severity: SevHigh,
	},

	// ─── HashiCorp Vault (1.10+) ────────────────────────────────────────────────
	{
		Name:     "Vault Service Token (hvs.)",
		Regex:    regexp.MustCompile(`\bhvs\.[A-Za-z0-9_\-]{24,}`),
		Severity: SevCritical,
	},
	{
		Name:     "Vault Batch Token (hvb.)",
		Regex:    regexp.MustCompile(`\bhvb\.[A-Za-z0-9_\-]{24,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Vault Recovery Token (hvr.)",
		Regex:    regexp.MustCompile(`\bhvr\.[A-Za-z0-9_\-]{24,}`),
		Severity: SevHigh,
	},

	// ─── PostHog ────────────────────────────────────────────────────────────────
	{
		Name:     "PostHog Personal API Key (phx_)",
		Regex:    regexp.MustCompile(`\bphx_[A-Za-z0-9]{30,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "PostHog Project API Key (phc_)",
		Regex:    regexp.MustCompile(`\bphc_[A-Za-z0-9]{30,}\b`),
		Severity: SevMedium,
	},

	// ─── Vercel (new prefixed tokens) ───────────────────────────────────────────
	{
		Name:     "Vercel Access Token (vcp_)",
		Regex:    regexp.MustCompile(`\bvcp_[A-Za-z0-9]{20,}\b`),
		Severity: SevHigh,
	},

	// ─── DigitalOcean (extra) ───────────────────────────────────────────────────
	{
		Name:     "DigitalOcean Functions Token (dof_v1_)",
		Regex:    regexp.MustCompile(`\bdof_v1_[a-f0-9]{64}\b`),
		Severity: SevHigh,
	},
	{
		// S3-compatible Spaces access keys are widely observed to start with DO00
		Name:     "DigitalOcean Spaces Access Key (DO00)",
		Regex:    regexp.MustCompile(`\bDO00[A-Z0-9]{16}\b`),
		Severity: SevHigh,
	},

	// ─── Databricks ─────────────────────────────────────────────────────────────
	{
		Name:     "Databricks Personal Access Token (dapi)",
		Regex:    regexp.MustCompile(`\bdapi[0-9a-f]{32}(?:-[0-9]+)?\b`),
		Severity: SevCritical,
	},

	// ─── Tailscale ──────────────────────────────────────────────────────────────
	{
		Name:     "Tailscale Auth/API Key (tskey-)",
		Regex:    regexp.MustCompile(`\btskey-(?:api|auth|client|webhook|scim)-[A-Za-z0-9]{8,}-[A-Za-z0-9]{20,}`),
		Severity: SevHigh,
	},

	// ─── Doppler ────────────────────────────────────────────────────────────────
	{
		Name:     "Doppler Token (dp.xx.)",
		Regex:    regexp.MustCompile(`\bdp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44}\b`),
		Severity: SevHigh,
	},

	// ─── Postman ────────────────────────────────────────────────────────────────
	{
		Name:     "Postman API Key (PMAK-)",
		Regex:    regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
		Severity: SevHigh,
	},

	// ─── Package registries ─────────────────────────────────────────────────────
	{
		Name:     "PyPI Upload Token (pypi-)",
		Regex:    regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`),
		Severity: SevHigh,
	},
	{
		Name:     "RubyGems API Key (rubygems_)",
		Regex:    regexp.MustCompile(`\brubygems_[a-f0-9]{48}\b`),
		Severity: SevHigh,
	},

	// ─── Sentry org/user auth tokens ────────────────────────────────────────────
	{
		Name:     "Sentry Auth Token (sntrys_/sntryu_)",
		Regex:    regexp.MustCompile(`\bsntr(?:ys|yu|ya)_[A-Za-z0-9_\-=+/]{40,}`),
		Severity: SevHigh,
	},

	// ─── Modern AI providers ────────────────────────────────────────────────────
	{
		Name:     "OpenRouter API Key (sk-or-v1-)",
		Regex:    regexp.MustCompile(`\bsk-or-v1-[a-f0-9]{64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Groq API Key (gsk_)",
		Regex:    regexp.MustCompile(`\bgsk_[A-Za-z0-9]{52}\b`),
		Severity: SevHigh,
	},

	// ─── (B) Context-based: no distinctive prefix, keyword required ──────────────
	{
		Name:       "Neon API Key (context)",
		Regex:      regexp.MustCompile(`(?i)neon[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{40,64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Upstash REST Token (context)",
		Regex:      regexp.MustCompile(`(?i)UPSTASH_(?:REDIS|KAFKA|QSTASH|VECTOR)_REST_TOKEN["\']?\s*[=:]\s*['"]?([A-Za-z0-9=_\-]{32,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Wasabi Access Key (context)",
		Regex:      regexp.MustCompile(`(?i)wasabi[_\-\s]*(?:access[_\-\s]*)?key(?:[_\-\s]*id)?["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{20})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES — BATCH 2 (keyhacks / TruffleHog / GitGuardian verified)
	// ════════════════════════════════════════════════════════════════════════════

	// ─── JFrog Artifactory ──────────────────────────────────────────────────────
	{
		Name:     "JFrog Access Token (AKCp)",
		Regex:    regexp.MustCompile(`\bAKCp[0-9A-Za-z]{59,70}`),
		Severity: SevCritical,
	},

	// ─── Atlassian / Bitbucket ──────────────────────────────────────────────────
	{
		Name:     "Atlassian API Token (ATATT3)",
		Regex:    regexp.MustCompile(`\bATATT3[A-Za-z0-9_\-=]{100,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Atlassian Scoped Access Token (ATCTT3)",
		Regex:    regexp.MustCompile(`\bATCTT3[A-Za-z0-9_\-=]{100,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Bitbucket App Password (ATBB)",
		Regex:    regexp.MustCompile(`\bATBB[A-Za-z0-9]{32,}`),
		Severity: SevHigh,
	},

	// ─── Figma ──────────────────────────────────────────────────────────────────
	{
		Name:     "Figma Access Token (figd_/figu_/figr_)",
		Regex:    regexp.MustCompile(`\bfig(?:d|u|r|oa)_[A-Za-z0-9_\-]{40,}`),
		Severity: SevHigh,
	},

	// ─── Fly.io (macaroon tokens) ───────────────────────────────────────────────
	{
		Name:     "Fly.io Token (fm2_)",
		Regex:    regexp.MustCompile(`\bfm2_[A-Za-z0-9_\-]{100,}`),
		Severity: SevCritical,
	},
	{
		Name:     "Fly.io Legacy Token (fo1_)",
		Regex:    regexp.MustCompile(`\bfo1_[A-Za-z0-9_\-]{40,}`),
		Severity: SevHigh,
	},

	// ─── LangSmith ──────────────────────────────────────────────────────────────
	{
		Name:     "LangSmith API Key (lsv2_)",
		Regex:    regexp.MustCompile(`\blsv2_(?:pt|sk)_[A-Za-z0-9]{32}_[a-f0-9]{10}\b`),
		Severity: SevHigh,
	},

	// ─── Pinecone (pcsk_ widely observed; also context-based) ───────────────────
	{
		Name:     "Pinecone API Key (pcsk_)",
		Regex:    regexp.MustCompile(`\bpcsk_[A-Za-z0-9_\-]{40,}`),
		Severity: SevHigh,
	},

	// ─── Brevo / SendinBlue ─────────────────────────────────────────────────────
	{
		Name:     "Brevo API Key (xkeysib-)",
		Regex:    regexp.MustCompile(`\bxkeysib-[a-z0-9]{64}-[A-Za-z0-9]{16}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Brevo SMTP Key (xsmtpsib-)",
		Regex:    regexp.MustCompile(`\bxsmtpsib-[a-z0-9]{64}-[A-Za-z0-9]{16}\b`),
		Severity: SevHigh,
	},

	// ─── Flutterwave ────────────────────────────────────────────────────────────
	{
		Name:     "Flutterwave Secret Key (FLWSECK...)",
		Regex:    regexp.MustCompile(`\bFLWSECK(?:_TEST)?-[a-f0-9]{32}-X\b`),
		Severity: SevCritical,
	},
	{
		Name:     "Flutterwave Public Key (FLWPUBK...)",
		Regex:    regexp.MustCompile(`\bFLWPUBK(?:_TEST)?-[a-f0-9]{32}-X\b`),
		Severity: SevMedium,
	},

	// ─── AI providers (modern, prefixed) ────────────────────────────────────────
	{
		Name:     "Perplexity API Key (pplx-)",
		Regex:    regexp.MustCompile(`\bpplx-[A-Za-z0-9]{40,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "xAI API Key (xai-)",
		Regex:    regexp.MustCompile(`\bxai-[A-Za-z0-9]{80}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Anthropic Admin Key (sk-ant-admin01-)",
		Regex:    regexp.MustCompile(`\bsk-ant-admin01-[A-Za-z0-9_\-]{93,110}`),
		Severity: SevCritical,
	},
	{
		Name:     "Fireworks AI Key (fw_)",
		Regex:    regexp.MustCompile(`\bfw_[A-Za-z0-9]{24,}\b`),
		Severity: SevHigh,
	},

	// ─── Misc SaaS (distinctive prefixes) ───────────────────────────────────────
	{
		Name:     "Shippo API Key",
		Regex:    regexp.MustCompile(`\bshippo_(?:live|test)_[a-f0-9]{40}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Typeform Personal Token (tfp_)",
		Regex:    regexp.MustCompile(`\btfp_[A-Za-z0-9_]{40,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Adafruit IO Key (aio_)",
		Regex:    regexp.MustCompile(`\baio_[A-Za-z0-9]{28}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "Amazon MWS Auth Token",
		Regex:    regexp.MustCompile(`\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Yandex API Key (AQVN)",
		Regex:    regexp.MustCompile(`\bAQVN[A-Za-z0-9_\-]{35,38}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "ClickUp Personal Token (pk_<id>_)",
		Regex:    regexp.MustCompile(`\bpk_\d{6,}_[A-Z0-9]{32}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Stytch Live Secret (secret-live-)",
		Regex:    regexp.MustCompile(`\bsecret-live-[A-Za-z0-9=_\-]{36,}\b`),
		Severity: SevCritical,
	},
	{
		Name:     "Stytch Test Secret (secret-test-)",
		Regex:    regexp.MustCompile(`\bsecret-test-[A-Za-z0-9=_\-]{36,}\b`),
		Severity: SevMedium,
	},

	// ─── (B) Context-based additions (no distinctive prefix) ────────────────────
	{
		Name:       "Segment Write Key (context)",
		Regex:      regexp.MustCompile(`(?i)segment[_\-\s]*(?:write[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "DataDog Application Key (context)",
		Regex:      regexp.MustCompile(`(?i)datadog[_\-\s]*app(?:lication)?[_\-\s]*key["\']?\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "ElevenLabs API Key (context)",
		Regex:      regexp.MustCompile(`(?i)xi[_\-]?api[_\-]?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Deepgram API Key (context)",
		Regex:      regexp.MustCompile(`(?i)deepgram[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([a-f0-9]{40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Together AI Key (context)",
		Regex:      regexp.MustCompile(`(?i)together[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Mistral API Key (context)",
		Regex:      regexp.MustCompile(`(?i)mistral[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES — BATCH 3 (final; keyhacks / TruffleHog / GitGuardian verified)
	// ════════════════════════════════════════════════════════════════════════════

	// ─── Context-free (distinctive prefix) ──────────────────────────────────────
	{
		Name:     "Resend API Key (re_)",
		Regex:    regexp.MustCompile(`\bre_[A-Za-z0-9_]{16,48}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Docker Hub Personal Access Token (dckr_pat_)",
		Regex:    regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_]{16,64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Render API Key (rnd_)",
		Regex:    regexp.MustCompile(`\brnd_[A-Za-z0-9_]{16,64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Pulumi Access Token (pul-)",
		Regex:    regexp.MustCompile(`\bpul-[a-f0-9]{40}\b`),
		Severity: SevCritical,
	},
	{
		Name:     "Xata API Key (xau_)",
		Regex:    regexp.MustCompile(`\bxau_[A-Za-z0-9_]{16,64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Ory API Key (ory_pat_/ory_apikey_/ory_wak_)",
		Regex:    regexp.MustCompile(`\bory_(?:pat|apikey|wak|st)_[A-Za-z0-9_\-]{20,}`),
		Severity: SevHigh,
	},
	{
		Name:     "Jina AI API Key (jina_)",
		Regex:    regexp.MustCompile(`\bjina_[A-Za-z0-9_]{16,64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Terraform Cloud / HCP Token (atlasv1)",
		Regex:    regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}`),
		Severity: SevCritical,
	},
	{
		Name:     "Ghost Admin API Key (id:secret)",
		Regex:    regexp.MustCompile(`\b[0-9a-f]{24}:[0-9a-f]{64}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "LaunchDarkly SDK/Mobile/API Key (sdk-/mob-/api-)",
		Regex:    regexp.MustCompile(`\b(?:sdk|mob|api)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "1Password Service Account Token (ops_)",
		Regex:    regexp.MustCompile(`\bops_eyJ[A-Za-z0-9_\-\.]{100,}`),
		Severity: SevCritical,
	},

	// ─── Context-based (no distinctive prefix; service keyword required) ─────────
	{
		Name:       "Mixpanel Secret (context)",
		Regex:      regexp.MustCompile(`(?i)mixpanel[_\-\s]*(?:project[_\-\s]*)?(?:token|secret|api[_\-\s]*secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Plaid Secret (context)",
		Regex:      regexp.MustCompile(`(?i)plaid[_\-\s]*(?:client[_\-\s]*id|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{24,32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Coinbase API Key (context)",
		Regex:      regexp.MustCompile(`(?i)coinbase[_\-\s]*(?:api[_\-\s]*)?(?:key|secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{16,64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Postmark Server Token (context)",
		Regex:      regexp.MustCompile(`(?i)postmark[_\-\s]*(?:server[_\-\s]*|account[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Mailjet API Key/Secret (context)",
		Regex:      regexp.MustCompile(`(?i)mailjet[_\-\s]*(?:api[_\-\s]*)?(?:key|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Pusher Key/Secret (context)",
		Regex:      regexp.MustCompile(`(?i)pusher[_\-\s]*(?:app[_\-\s]*)?(?:key|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{20,32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "OneSignal REST API Key (context)",
		Regex:      regexp.MustCompile(`(?i)onesignal[_\-\s]*(?:rest[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9=_\-]{40,64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Trello Key/Token (context)",
		Regex:      regexp.MustCompile(`(?i)trello[_\-\s]*(?:api[_\-\s]*)?(?:key|token|secret)["\']?\s*[=:]\s*['"]?([a-f0-9]{32,64})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Monday.com API Token (context)",
		Regex:      regexp.MustCompile(`(?i)monday[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Webflow API Token (context)",
		Regex:      regexp.MustCompile(`(?i)webflow[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([a-f0-9]{64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Elastic Cloud API Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:elastic|elasticsearch)[_\-\s]*(?:cloud[_\-\s]*)?(?:api[_\-\s]*)?(?:key|id)["\']?\s*[=:]\s*['"]?([A-Za-z0-9=]{40,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Backblaze B2 Application Key (context)",
		Regex:      regexp.MustCompile(`(?i)(?:b2|backblaze)[_\-\s]*(?:application[_\-\s]*)?key(?:[_\-\s]*id)?["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{25,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Zoom Client/SDK Secret (context)",
		Regex:      regexp.MustCompile(`(?i)zoom[_\-\s]*(?:client[_\-\s]*secret|api[_\-\s]*secret|sdk[_\-\s]*secret)["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{30,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Bugsnag API Key (context)",
		Regex:      regexp.MustCompile(`(?i)bugsnag[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Rollbar Access Token (context)",
		Regex:      regexp.MustCompile(`(?i)rollbar[_\-\s]*(?:access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "AssemblyAI API Key (context)",
		Regex:      regexp.MustCompile(`(?i)assemblyai[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Stability AI Key (context)",
		Regex:      regexp.MustCompile(`(?i)stability[_\-\s]*(?:ai[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?(sk-[A-Za-z0-9]{40,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Klaviyo Private Key (context)",
		Regex:      regexp.MustCompile(`(?i)klaviyo[_\-\s]*(?:private[_\-\s]*)?(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?(pk_[a-zA-Z0-9]{34})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Netlify Access Token (context)",
		Regex:      regexp.MustCompile(`(?i)netlify[_\-\s]*(?:auth[_\-\s]*|api[_\-\s]*|access[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Fastly API Token (context)",
		Regex:      regexp.MustCompile(`(?i)fastly[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Snyk API Token (context)",
		Regex:      regexp.MustCompile(`(?i)snyk[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Sanity API Token (context)",
		Regex:      regexp.MustCompile(`(?i)sanity[_\-\s]*(?:api[_\-\s]*)?(?:token|key)["\']?\s*[=:]\s*['"]?(sk[A-Za-z0-9]{30,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Vonage/Nexmo API Secret (context)",
		Regex:      regexp.MustCompile(`(?i)(?:vonage|nexmo)[_\-\s]*(?:api[_\-\s]*)?secret["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{16})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Honeycomb API Key (context)",
		Regex:      regexp.MustCompile(`(?i)honeycomb[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{22,32})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Hasura Admin Secret (context)",
		Regex:      regexp.MustCompile(`(?i)hasura[_\-\s]*(?:graphql[_\-\s]*)?admin[_\-\s]*secret["\']?\s*[=:]\s*['"]?([A-Za-z0-9_\-]{8,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Meilisearch Master Key (context)",
		Regex:      regexp.MustCompile(`(?i)meili(?:search)?[_\-\s]*(?:master[_\-\s]*|api[_\-\s]*)?key["\']?\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Codecov Upload Token (context)",
		Regex:      regexp.MustCompile(`(?i)codecov[_\-\s]*(?:upload[_\-\s]*)?token["\']?\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},


	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES — BATCH 4 (verified against official docs, 2026)
	// ════════════════════════════════════════════════════════════════════════════

	// ─── Alibaba / Tencent Cloud (confirmed: LTAI prefix + AKID prefix) ──────
	{
		Name:     "Alibaba Cloud AccessKey ID (LTAI)",
		Regex:    regexp.MustCompile(`\bLTAI[A-Za-z0-9]{20}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Tencent Cloud SecretId (AKID)",
		Regex:    regexp.MustCompile(`\bAKID[A-Za-z0-9]{17,40}\b`),
		Severity: SevHigh,
	},

	// ─── Rust package registry (confirmed: crates.io maintainer) ─────────────
	{
		Name:     "crates.io API Token (cio)",
		Regex:    regexp.MustCompile(`\bcio[A-Za-z0-9]{32}\b`),
		Severity: SevHigh,
	},

	// ─── AI providers 2025-2026 (verified prefixes) ─────────────────────────
	{
		Name:     "Cerebras API Key (csk-)",
		Regex:    regexp.MustCompile(`\bcsk-[A-Za-z0-9_\-]{32,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "NVIDIA NIM API Key (nvapi-)",
		Regex:    regexp.MustCompile(`\bnvapi-[A-Za-z0-9_\-]{32,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Voyage AI API Key (pa-)",
		Regex:    regexp.MustCompile(`\bpa-[A-Za-z0-9_\-]{40,}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "DeepSeek / Kimi / OpenAI-compat key (sk- context)",
		Regex:      regexp.MustCompile(`(?i)(?:deepseek|kimi|moonshot|zhipu|glm)[_\-\s]*(?:api[_\-\s]*)?(?:key|token)["\']?\s*[=:]\s*['"]?(sk-[A-Za-z0-9_\-]{30,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Cloudflare Turnstile ─────────────────────────────────────────────────
	{
		Name:     "Cloudflare Turnstile Secret Key (0x3AAAA)",
		Regex:    regexp.MustCompile(`\b0x3AAAA[A-Za-z0-9_\-]{30,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Cloudflare Turnstile Site Key (0x4AAAA)",
		Regex:    regexp.MustCompile(`\b0x4AAAA[A-Za-z0-9_\-]{30,}\b`),
		Severity: SevMedium,
	},

	// ─── Meta ─────────────────────────────────────────────────────────────────
	{
		Name:     "WhatsApp Cloud API Token (EAAG)",
		Regex:    regexp.MustCompile(`\bEAAG[A-Za-z0-9]{40,}\b`),
		Severity: SevHigh,
	},

	// ─── SSH / Keys ───────────────────────────────────────────────────────────
	{
		Name:     "PuTTY Private Key (PPK)",
		Regex:    regexp.MustCompile(`PuTTY-User-Key-File-[23]:`),
		Severity: SevCritical,
	},

	// ─── DB / Connection Strings ─────────────────────────────────────────────
	{
		Name:     "URI with embedded credentials",
		Regex:    regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[A-Za-z0-9._%+\-]+:[^@/\s]{2,}[@][A-Za-z0-9.\-]+(?::[0-9]+)?(?:/|$|\s)`),
		Severity: SevHigh,
	},
	{
		Name:     "Oracle JDBC Thin URL",
		Regex:    regexp.MustCompile(`jdbc:oracle:thin:@?[A-Za-z0-9._%+\-]+/[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+(?::[0-9]+)?/[A-Za-z0-9_\-]+`),
		Severity: SevHigh,
	},

	// ─── Generic credential files ────────────────────────────────────────────
	{
		Name:       ".netrc credentials (machine login password)",
		Regex:      regexp.MustCompile(`(?i)machine\s+[^\s]+\s+login\s+[^\s]+\s+password\s+([^\s]+)`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "PostgreSQL .pgpass entry",
		Regex:    regexp.MustCompile(`(?m)^[A-Za-z0-9.\-*]+\:[0-9*]+:[A-Za-z0-9_\-*]+:[A-Za-z0-9_\-*]+:[^\s]+`),
		Severity: SevLow,
	},
	{
		Name:       "Authorization: Basic header",
		Regex:      regexp.MustCompile(`(?i)authorization\s*:\s*basic\s+([A-Za-z0-9+/]{12,}={0,2})`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		// BUGFIX binus-2026-09: getApiAuthToken="Basic <b64>" (assignment form,
		// bukan header) lolos — pola lama mensyaratkan prefix "authorization:".
		Name:       "Basic Auth Token in code",
		Regex:      regexp.MustCompile(`(?i)(?:\w*?(?:auth[_\-]?token|token|authorization|basic[_\-]?auth|secret|key))["']?\s*[=:]\s*['"]Basic\s+([A-Za-z0-9+/]{16,}={0,2})['"]`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},


	// ════════════════════════════════════════════════════════════════════════════
	// HUMAN / LEFTOVER CREDENTIALS  (v2.1.1 — tightened vs minified-JS FP)
	// Catches HTB-style leaks; anti-FP in isHumanCredFP() (main.go).
	// ════════════════════════════════════════════════════════════════════════════

	// HTML comment + context keyword + user:pass
	// Lab: <!-- TODO: remove test credentials admin:HiddenInPlainSight -->
	{
		Name:       "HTML comment credentials (user:pass)",
		Regex:      regexp.MustCompile(`(?i)<!--[^>]{0,400}?(?:credentials?|password|passwd|todo|default\s+(?:pass|user|cred|login)|test\s+(?:pass|user|cred|account|login)|login\s*(?:with|as|is|:)|username\s*[:=]|pass(?:word)?\s*[:=])[^>]{0,100}?\b([A-Za-z][A-Za-z0-9._+\-]{1,32}:[A-Za-z0-9!@#$%^&*_\-.]{6,48})\b[^>]*-->`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// Real // line comments only (NOT https://). Short window. Strict keywords.
	// (?m)(^|[^:/\w.])//  → comment start after BOL/whitespace/punct, never after ":" (URL scheme)
	{
		Name:       "JS/line comment credentials (user:pass)",
		Regex:      regexp.MustCompile(`(?im)(?:^|[^:/\w.])//[ \t]*[^\n]{0,200}?(?:credentials?|password|passwd|todo|default\s+(?:pass|user|cred|login)|test\s+(?:pass|user|cred|account|login)|login\s*(?:with|as|is|:))[^\n]{0,80}?\b([A-Za-z][A-Za-z0-9._+\-]{1,32}:[A-Za-z0-9!@#$%^&*_\-.]{6,48})\b`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// /* block comment */ — limited span, strict keywords (avoid huge minified /*...*/)
	{
		Name:       "Block comment credentials (user:pass)",
		Regex:      regexp.MustCompile(`(?i)/\*[^*]{0,300}?(?:credentials?|password|passwd|todo|default\s+(?:pass|user|cred|login)|test\s+(?:pass|user|cred|account|login))[^*]{0,80}?\b([A-Za-z][A-Za-z0-9._+\-]{1,32}:[A-Za-z0-9!@#$%^&*_\-.]{6,48})\b[^*]{0,80}?\*/`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// Freeform near strong keyword only (no bare "login"/"default"/"secret")
	{
		Name:       "Freeform credentials near keyword (user:pass)",
		Regex:      regexp.MustCompile(`(?i)(?:credentials?|default\s+(?:credentials?|password|login|user)|test\s+(?:credentials?|password|account|user|login)|demo\s+(?:credentials?|account|user|login)|login\s*(?:with|as|is)\s+|user(?:name)?\s*/\s*pass(?:word)?)\s*[:=]?\s*([A-Za-z][A-Za-z0-9._+\-]{1,32}:[A-Za-z0-9!@#$%^&*_\-.]{6,48})\b`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	// Password assignment — QUOTED only (bare unquoted = minified-JS bloodbath)
	{
		Name:       "Password assignment (quoted or bare)",
		Regex:      regexp.MustCompile(`(?i)(?:^|[^.\w])(?:password|passwd|pwd|passphrase)\s*[=:]\s*["']([^"'\s]{6,64})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	// Bare password=value only in env/config-like context (KEY=val, no dots before password)
	{
		Name:       "Password assignment bare (env/config)",
		Regex:      regexp.MustCompile(`(?im)(?:^|[\s;,&])(?:password|passwd|pwd|db_password|db_pass|mysql_password|postgres_password|redis_password)\s*=\s*([A-Za-z0-9!@#$%^&*_\-./+]{6,64})(?:\s|$|["'#;])`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	// username=X password=Y — quoted values preferred; allow bare alnum secrets
	{
		Name:     "Username + Password pair assignment",
		Regex:    regexp.MustCompile(`(?i)(?:user(?:name)?|login|uid)\s*[=:]\s*["']([A-Za-z0-9._\-@+]{2,40})["']\s*[,;\s|&]{1,8}\s*(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{4,64})["']`),
		Severity: SevHigh,
	},
	// <input type=password value="secret">
	{
		Name:       "Hardcoded password input value",
		Regex:      regexp.MustCompile(`(?i)<input\b[^>]{0,200}?\btype\s*=\s*["']?password["']?[^>]{0,200}?\bvalue\s*=\s*["']([^"']{4,64})["']`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Hardcoded password input value (value before type)",
		Regex:      regexp.MustCompile(`(?i)<input\b[^>]{0,200}?\bvalue\s*=\s*["']([^"']{4,64})["'][^>]{0,200}?\btype\s*=\s*["']?password["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES BATCH 5 — verified formats (2026): AI agents, payments,
	// observability, web3, maps/weather, misc SaaS
	// ════════════════════════════════════════════════════════════════════════════

	// ─── AI agents / search / scraping ────────────────────────────────────────
	{
		Name:     "Tavily API Key (tvly-)",
		Regex:    regexp.MustCompile(`\btvly-(?:dev-|prod-)?[A-Za-z0-9_\-]{16,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "Firecrawl API Key (fc-)",
		Regex:    regexp.MustCompile(`\bfc[-_][A-Za-z0-9]{16,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "LlamaCloud / LlamaIndex Key (llx-)",
		Regex:    regexp.MustCompile(`\bllx-[A-Za-z0-9_\-]{16,}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "Serper.dev API Key (context)",
		Regex:      regexp.MustCompile(`(?i)serper[^"\n]{0,40}?(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']([a-f0-9]{32})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "Exa AI API Key (context)",
		Regex:      regexp.MustCompile(`(?i)\bexa[_\-\s]*(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']([A-Za-z0-9_\-]{32,64})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "SerpAPI Key (context)",
		Regex:      regexp.MustCompile(`(?i)serpapi[^"\n]{0,40}?(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']([a-f0-9]{32,64})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Auth / SaaS ──────────────────────────────────────────────────────────
	{
		Name:     "WorkOS Secret Key (sk_test/sk_prod/sk_live)",
		Regex:    regexp.MustCompile(`\bsk_(?:test|prod|live|example)_[A-Za-z0-9]{16,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Cal.com API Key (cal_live/cal_test)",
		Regex:    regexp.MustCompile(`\bcal_(?:live|test)_[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevHigh,
	},

	// ─── Observability / logs ─────────────────────────────────────────────────
	{
		Name:     "Grafana Cloud Access Policy Token (glc_)",
		Regex:    regexp.MustCompile(`\bglc_[A-Za-z0-9+/=_\-\.]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Axiom.co Dataset Token (xaat-)",
		Regex:    regexp.MustCompile(`\bxaat-[A-Za-z0-9_\-]{16,}\b`),
		Severity: SevMedium,
	},
	{
		Name:       "Splunk HEC Token (context)",
		Regex:      regexp.MustCompile(`(?i)\b(?:splunk[_\-\s]*(?:hec[_\-\s]*)?(?:token|key)|hec[_\-\s]*token)["\']?\s*[:=]\s*["']?([a-f0-9]{32,64})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Payments ─────────────────────────────────────────────────────────────
	{
		Name:     "Adyen API Key (AQE…)",
		Regex:    regexp.MustCompile(`\bAQE[A-Za-z0-9+/=_\-]{60,140}\b`),
		Severity: SevCritical,
	},

	// ─── Infra / hosting ──────────────────────────────────────────────────────
	{
		Name:       "Heroku API Key (UUID, context)",
		Regex:      regexp.MustCompile(`(?i)heroku[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:     "Netlify Personal Access Token (nfp_)",
		Regex:    regexp.MustCompile(`\bnfp_[A-Za-z0-9_\-]{36,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Oracle Cloud ID (ocid1)",
		Regex:    regexp.MustCompile(`\bocid1\.[a-z]+\.(?:oc1|oc2|oc3|eu-frankfurt-1)\.\.[a-z0-9]+(\.[a-z2-7]+)*\b`),
		Severity: SevLow,
	},

	// ─── GitLab extra token types ─────────────────────────────────────────────
	{
		Name:     "GitLab OAuth App Secret (gloas-)",
		Regex:    regexp.MustCompile(`\bgloas-[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "GitLab Pipeline Trigger Token (glptt-)",
		Regex:    regexp.MustCompile(`\bglptt-[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "GitLab Feed Token (glfeed-)",
		Regex:    regexp.MustCompile(`\bglfeed-[A-Za-z0-9_\-]{20,}\b`),
		Severity: SevLow,
	},

	// ─── Web3 ─────────────────────────────────────────────────────────────────
	{
		Name:       "Etherscan-family Explorer Key (context)",
		Regex:      regexp.MustCompile(`(?i)\b(?:etherscan|bscscan|polygonscan|arbiscan|basescan|snowtrace|optimistic[\.\-]?etherscan)[_\-]?[^"\n]{0,60}?(?:apikey|api[_\-\s]*key|token)["\']?\s*[:=]?\s*["']?\b([A-Za-z0-9]{32,40})\b`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Infura Project Key (context)",
		Regex:      regexp.MustCompile(`(?i)infura[^"\n]{0,40}?(?:project[_\-\s]*)?(?:id|secret|key)["\']?\s*[:=]\s*["']?([a-f0-9]{32})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Moralis Web3 API Key (context)",
		Regex:      regexp.MustCompile(`(?i)moralis[^"\n]{0,60}?["']([A-Za-z0-9+/=_\-]{80,})["']`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Alchemy API Key (context)",
		Regex:      regexp.MustCompile(`(?i)alchemy[^"\n]{0,60}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*["']([A-Za-z0-9_\-]{25,60})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Maps / weather / news (frontend favorites) ───────────────────────────
	{
		Name:       "OpenWeatherMap appid",
		Regex:      regexp.MustCompile(`(?i)\bappid["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "DeepL API Key (free :fx)",
		Regex:      regexp.MustCompile(`\b[0-9a-f]{32}:fx\b`),
		Severity:   SevHigh,
	},
	{
		Name:       "DeepL API Key (context)",
		Regex:      regexp.MustCompile(`(?i)deepl[^"\n]{0,40}?["']([0-9a-f]{32})(?::fx)?["']`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "NewsAPI Key (context)",
		Regex:      regexp.MustCompile(`(?i)newsapi[^"\n]{0,40}?(?:key|token)?["'\s]*[:=]\s*["']([a-f0-9]{32})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "OpenCage Geocoder Key (context)",
		Regex:      regexp.MustCompile(`(?i)opencage[^"\n]{0,40}?(?:key|apikey)["\']?\s*[:=]\s*["']([a-f0-9]{32})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "HERE Maps API Key (context)",
		Regex:      regexp.MustCompile(`(?i)\bhere[._\-\s]*(?:maps[._\-\s]*)?(?:api[._\-\s]*)?(?:key|id|secret)["\']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,64})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},

	// ─── Misc SaaS ────────────────────────────────────────────────────────────
	{
		Name:     "Apify API Token (apify_api_)",
		Regex:    regexp.MustCompile(`\bapify_api_[A-Za-z0-9]{20,}\b`),
		Severity: SevMedium,
	},
	{
		Name:     "n8n Personal API Key (n8n_api_)",
		Regex:    regexp.MustCompile(`\bn8n_api_[A-Za-z0-9]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:     "Zoho OAuth Token (1000.xxx)",
		Regex:    regexp.MustCompile(`\b1000\.[0-9a-f]{38,44}\b`),
		Severity: SevMedium,
	},
	{
		Name:       "Typesense API Key (context)",
		Regex:      regexp.MustCompile(`(?i)typesense[^"\n]{0,60}?(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Weights & Biases API Key (context)",
		Regex:      regexp.MustCompile(`(?i)wandb[^"\n]{0,40}?(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']?([a-f0-9]{40})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "MessageBird Access Key (live_/test_, context)",
		Regex:      regexp.MustCompile(`(?i)messagebird[^"\n]{0,60}?(?:access[_\-\s]*)?key["\']?\s*[:=]\s*["']?((?:live|test)_[A-Za-z0-9]{20,30})["']?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Braze REST API Key (context)",
		Regex:      regexp.MustCompile(`(?i)braze[^"\n]{0,60}?(?:rest|api)[_\-\s]*(?:key|token)["\']?\s*[:=]\s*["']([A-Za-z0-9\-]{30,50})["']`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Statsig Server Secret (context)",
		Regex:      regexp.MustCompile(`(?i)statsig[^"\n]{0,60}?["'](secret-[A-Za-z0-9\-]{20,})["']`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Pipedrive API Token (context)",
		Regex:      regexp.MustCompile(`(?i)pipedrive[^"\n]{0,40}?(?:api[_\-\s]*token|api[_\-\s]*key|token)["\']?\s*[:=]\s*["']?([a-f0-9]{40})["']?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Jotform API Key (context)",
		Regex:      regexp.MustCompile(`(?i)jotform[^"\n]{0,40}?(?:api[_\-\s]*)?key["\']?\s*[:=]\s*["']([a-f0-9]{32})["']`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "Kaggle Credential (username+key json)",
		Regex:      regexp.MustCompile(`(?i)\{"username"[^}]{0,80}?"key"\s*:\s*"([a-f0-9]{32})"\}`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Pushover Key (context)",
		Regex:      regexp.MustCompile(`(?i)pushover[^"\n]{0,60}?(?:user|application|app)?[_\-\s]?(?:key|token)["\']?\s*[:=]\s*["']?([A-Za-z0-9]{30})["']?`),
		Severity:   SevLow,
		MatchGroup: 1,
	},


	// ════════════════════════════════════════════════════════════════════════════
	// NEW SERVICES — BATCH 6 (verified active 2026, context-based, FP-safe)
	// Keep legacy patterns; only ADD. Most use keyword + value capture.
	// ════════════════════════════════════════════════════════════════════════════

	// ─── Infra / Cloud active ─────────────────────────────────────────────────
	{
		Name:       "Hetzner Cloud API Token (64, context)",
		Regex:      regexp.MustCompile(`(?i)(?:hetzner|hcloud)[^"\n]{0,40}?(?:api[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9]{64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:     "Scaleway Access Key (SCW)",
		Regex:    regexp.MustCompile(`\bSCW[A-Z0-9]{17,}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "Scaleway Secret Key (context)",
		Regex:      regexp.MustCompile(`(?i)scaleway[^"\n]{0,40}?secret[^"\n]{0,20}?["\']([A-Za-z0-9+/=]{40,})['"]`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Vultr API Key (context)",
		Regex:      regexp.MustCompile(`(?i)vultr[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([a-f0-9\-]{32,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Linode Personal Access Token (context)",
		Regex:      regexp.MustCompile(`(?i)linode[^"\n]{0,40}?(?:api[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([a-f0-9]{60,64})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "OVH API Key (context)",
		Regex:      regexp.MustCompile(`(?i)ovh[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token|application[_\-\s]*key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9]{20,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Railway API Token (context)",
		Regex:      regexp.MustCompile(`(?i)railway[^"\n]{0,40}?(?:api[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{24,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "BunnyCDN / Bunny Storage API Key (context)",
		Regex:      regexp.MustCompile(`(?i)bunny[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([a-f0-9\-]{32,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── AI / GPU active 2025-2026 ────────────────────────────────────────────
	{
		Name:       "Fal.ai API Key (key_id:sk_live_...)",
		Regex:      regexp.MustCompile(`\b[a-z0-9]{6,16}:sk_live_[A-Za-z0-9]{16,}\b`),
		Severity:   SevHigh,
	},
	{
		Name:     "RunPod API Key (rpa_)",
		Regex:    regexp.MustCompile(`\brpa_[A-Za-z0-9]{20,}\b`),
		Severity: SevHigh,
	},
	{
		Name:       "Modal API Key (context)",
		Regex:      regexp.MustCompile(`(?i)modal[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:       "Tinybird API Token (context)",
		Regex:      regexp.MustCompile(`(?i)tinybird[^"\n]{0,40}?(?:api[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:     "Turso Database URL (libsql://)",
		Regex:    regexp.MustCompile(`\blibsql://[A-Za-z0-9.\-]+\.turso\.io\b`),
		Severity: SevMedium,
	},

	// ─── CDN / Media ──────────────────────────────────────────────────────────
	{
		Name:       "Mux Token ID (context)",
		Regex:      regexp.MustCompile(`(?i)mux[^"\n]{0,40}?token[_\-\s]*id["\']?\s*[:=]\s*['"]?([a-f0-9\-]{32,40})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Mux Token Secret (context)",
		Regex:      regexp.MustCompile(`(?i)mux[^"\n]{0,40}?token[_\-\s]*secret["\']?\s*[:=]\s*['"]?([A-Za-z0-9+/=]{30,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		Name:       "Imgix Signing Key (context)",
		Regex:      regexp.MustCompile(`(?i)imgix[^"\n]{0,40}?(?:signing[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([a-f0-9]{32,64})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Payments ─────────────────────────────────────────────────────────────
	{
		Name:       "Paddle API Key (context)",
		Regex:      regexp.MustCompile(`(?i)paddle[^"\n]{0,40}?(?:api[_\-\s]*)?(?:key|token)["\']?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},

	// ─── Observability ────────────────────────────────────────────────────────
	{
		Name:     "Honeybadger API Key (hbp_)",
		Regex:    regexp.MustCompile(`\bhbp_[A-Za-z0-9]{20,}\b`),
		Severity: SevMedium,
	},
	{
		Name:       "Better Stack / Logtail Source Token (context)",
		Regex:      regexp.MustCompile(`(?i)(?:better[_\-]?stack|logtail)[^"\n]{0,40}?(?:source[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

	// ─── Dev / Automation ─────────────────────────────────────────────────────
	{
		Name:       "Deno Deploy Token (context)",
		Regex:      regexp.MustCompile(`(?i)deno[^"\n]{0,40}?(?:deploy[_\-\s]*)?(?:token|key)["\']?\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
		{
		Name:       "Cloudflare R2 S3 URL (r2.cloudflarestorage.com)",
		Regex:      regexp.MustCompile(`https?://[a-z0-9.\-]+\.r2\.cloudflarestorage\.com`),
		Severity:   SevLow,
	},


	// ─── Generic Sensitive Patterns ───────────────────────────────────────────────
	// Restrict value to non-space chars only — prevents matching UI strings like
	// "Forgot password?", "Enter your password", "Reset your password", etc.
	{
		Name:       "Generic Secret / Password in code",
		Regex:      regexp.MustCompile(`(?i)(?:password|passwd|secret|private[_\-]?key|client[_\-]?secret|auth[_\-]?token|access[_\-]?token)["\']?\s*[=:]\s*['"]([A-Za-z0-9!@#$%^&*_\-.+][A-Za-z0-9!@#$%^&*_\-./+]{7,79})['"]`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	// Restrict value to alphanumeric+dash/underscore — prevents matching placeholders
	// like "your-key-here", "your-venice-api-key", UI labels, etc.
	{
		Name:       "Generic API Key in code",
		Regex:      regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|app[_\-]?key|appkey)["\']?\s*[=:]\s*['"]([A-Za-z0-9_\-]{10,80})['"]`),
		Severity:   SevLow,
		MatchGroup: 1,
	},
	{
		Name:       "Bearer Token in code",
		Regex:      regexp.MustCompile(`(?i)(?:bearer|authorization)["\']?\s*[=:]\s*['"]?Bearer\s+([A-Za-z0-9_\-\.]{20,})['"]?`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},
	{
		Name:     "GCP Service Account Email",
		Regex:    regexp.MustCompile(`\b[a-z][a-z0-9\-]{4,28}@[a-z][a-z0-9\-]{4,28}\.iam\.gserviceaccount\.com\b`),
		Severity: SevMedium,
	},
	{
		// BUGFIX binus-2026-09: REDPER="%v$4T!9CRqE_[G-=" (kunci enkripsi custom
		// untuk auth token di localStorage) — tidak ada pola key-name generik.
		Name:       "Encryption Key in code",
		Regex:      regexp.MustCompile(`(?i)(?:redper|enc(?:ryption)?[_\-]?(?:key|pass(?:word|phrase)?)|crypto[_\-]?key|secret[_\-]?key)["']?\s*[=:]\s*['"]([^'"\s]{6,64})['"]`),
		Severity:   SevHigh,
		MatchGroup: 1,
	},
	{
		// BUGFIX binus-2026-09: clientId AzureAD/MSAL (UUID kontekstual).
		Name:       "OAuth Client ID (UUID)",
		Regex:      regexp.MustCompile(`(?i)(?:client[_\-]?id|application[_\-]?(?:client[_\-]?)?id)["']?\s*[=:]\s*['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]`),
		Severity:   SevMedium,
		MatchGroup: 1,
	},

}
