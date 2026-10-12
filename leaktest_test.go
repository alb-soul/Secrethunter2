package main

import "testing"

// ── leaktest-2026-10 ronde-1: pola baru ──
func TestLeaktestNewPatterns(t *testing.T) {
	fired(t, `const K="pk_test_51Ab3TestLeak7192XyZabcdefgh"`, "Stripe Test Publishable/Restricted Key", "MEDIUM")
	fired(t, `u="https://x-demo-1-default-rtdb.firebaseio.com"`, "Firebase Realtime Database URL", "LOW")
	fired(t, `id="123456789012-testleakabcdefghij012345.apps.googleusercontent.com"`, "Google OAuth Client ID", "MEDIUM")
	fired(t, `pass: "TestLeak456"`, "Password assignment (pass/pwd)", "LOW")
	// pwd dicover pola lama (dedup by match -> pola lama menang, ekspektasi dipertahankan)
	fired(t, `pwd="DbPass2026!"`, "Password assignment (quoted or bare)", "MEDIUM")
	fired(t, `smtp_pass = "MailPass2026!"`, "Password assignment (pass/pwd)", "LOW")
	// zzz-density: kunci asli ber-zzzz tetap ketemu
	fired(t, `key AKIA7Q9XTEZZZLEAK004 here`, "AWS Access Key ID", "CRITICAL")
	// guard presisi: bypass/compass bukan password
	notFired(t, `bypass: "abcdefghijklmnopqrstuvwxyz012345"`, "Password assignment (pass/pwd)")
	notFired(t, `compass: "northstar2026!"`, "Password assignment (pass/pwd)")
}

// ── leaktest-2026-10 ronde-1: decode layer ──
func TestLeaktestDecodeLayer(t *testing.T) {
	// split-concat "ghp_"+"..."
	fired(t, `var e="ghp_"+"TestLeak0723456789abcdefghij07654321"`, "GitHub Personal Access Token (ghp_) (decoded)", "")
	// hex escapes -> AKIAWWWWTESTLEAK0002
	fired(t, `var t="\x41\x4b\x49\x41\x57\x57\x57\x57\x54\x45\x53\x54\x4c\x45\x41\x4b\x30\x30\x30\x32"`, "AWS Access Key ID (decoded)", "")
	// fromCharCode -> AKIA7Q9XTESTLEAK00041
	fired(t, `var n=String.fromCharCode(65,75,73,65,55,81,57,88,84,69,90,90,90,76,69,65,75,48,48,52)`, "AWS Access Key ID (decoded)", "")
	// reversed
	fired(t, `var o="400KAELZZZETX9Q7AIKA".split("").reverse().join("")`, "AWS Access Key ID (decoded)", "")
	// base64 -> SG.TestLeak... (22/43)
	fired(t, `var a=atob("U0cuVGVzdExlYWswMTIzNDU2Nzg5YWJjZC5qa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9w")`, "SendGrid API Key (decoded)", "")
	// data:-URI tidak di-decode (anti-FP font/gambar)
	notFired(t, `src:url(data:font/woff2;base64,d09GRgABAAAAAGywABMAAAABrEAAAQAAAAAAAAAAAAAAAAAAAAAAAAAABPUy8yAAAB)`, "SendGrid API Key (decoded)")
}
