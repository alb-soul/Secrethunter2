package main

import "testing"

// ── leaktest-2026-10 ronde-1c: koma-declarator (norma minified) ──
func TestLeaktestCommaDecl(t *testing.T) {
	// literal inline matchable -> base ketemu plain (propagate tak perlu, dedup menang)
	fired(t, `var e="x",n="AKIA7Q9XTEZZZLEAK004",i={k:n};`, "AWS Access Key ID", "CRITICAL")
	// literal inline TAK matchable (butuh konteks key) + koma-decl + use berkunci
	// -> hanya propagasi yg menautkan: strict AWS Secret (decoded)
	fired(t, `var t=1,n="wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY000",i={aws_secret_access_key:n};`,
		"AWS Secret Access Key (decoded)", "CRITICAL")
	// reassignment membatalkan propagasi, tapi literal inline tetap ketemu plain
	fired(t, `var n="AKIA7Q9XTEZZZLEAK004";n="other";i={k:n};`, "AWS Access Key ID", "CRITICAL")
}
