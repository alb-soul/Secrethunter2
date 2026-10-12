package main

import "testing"

// ── leaktest-2026-10 ronde-1b: propagasi konstanta + secret_*key ──
func TestLeaktestPropagate(t *testing.T) {
	// var n="LIT" + {key:n} -> strict AWS Secret (decoded)
	fired(t, `var n="wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY000",i={aws_secret_access_key:n};`,
		"AWS Secret Access Key (decoded)", "CRITICAL")
	// split + propagate berantai
	fired(t, `var e="ghp_"+"QwEr0987654321TyUiOpMnBjHgFdSaKlZxCv",i={github_token:e};`,
		"GitHub Personal Access Token (ghp_) (decoded)", "")
	// secret_access_key tanpa prefix aws (Generic)
	fired(t, `"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY000"`,
		"Generic Secret / Password in code", "LOW")
	// dipakai 2x -> tak dipropagasi, tapi literal inline tetap ketemu plain
	fired(t, `var n="AKIA7Q9XTEZZZLEAK004",i={a:n,b:n};`, "AWS Access Key ID", "CRITICAL")
	// shorthand {k} tak dipropagasi (base tetap ketemu plain)
	fired(t, `var k="AKIA7Q9XTEZZZLEAK004",o={k};`, "AWS Access Key ID", "CRITICAL")
}
