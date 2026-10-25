package main

import "testing"

// ── audit 2026-10-25: fintech ID + SaaS baru ──
func TestNewServices2026(t *testing.T) {
	// Midtrans: server = rahasia, client = publik
	fired(t, `serverKey = "SB-Mid-server-Qw8eR7tY6uI5oP4aS3dF"`, "Midtrans Server Key", "CRITICAL")
	fired(t, `serverKey = "Mid-server-Xy9aBcDeFgHiJkLm"`, "Midtrans Server Key", "CRITICAL")
	fired(t, `clientKey = "SB-Mid-client-Qw8eR7tY6uI5oP4aS3dF"`, "Midtrans Client Key (public)", "INFO")

	// Xendit (contoh resmi docs; charset + / =)
	fired(t, `key = "xnd_development_P4qDfOss0OCpl8RtKrROHjaQYNCk9dN5lSfk+R1l9Wbe+rSiCwZ3jw=="`,
		"Xendit Secret API Key", "CRITICAL")
	fired(t, `key = "xnd_production_Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp=="`,
		"Xendit Secret API Key", "CRITICAL")

	// WooCommerce ck_/cs_ 40 hex
	ck := "ck_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
	cs := "cs_" + "b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1"
	fired(t, `k = "`+ck+`"`, "WooCommerce API Key (ck_/cs_)", "HIGH")
	fired(t, `s = "`+cs+`"`, "WooCommerce API Key (ck_/cs_)", "HIGH")

	// Langfuse (uuid)
	fired(t, `LANGFUSE_SECRET_KEY = "sk-lf-123e4567-e89b-12d3-a456-426614174000"`,
		"Langfuse Secret Key", "HIGH")
	fired(t, `LANGFUSE_PUBLIC_KEY = "pk-lf-123e4567-e89b-12d3-a456-426614174000"`,
		"Langfuse Public Key (public)", "INFO")

	// NuGet oy2 + 43
	nu := "oy2" + "b7k2m9p4r1t6w3y8n5q0s7v2x9z4c1f6h3j8l5d0g7e"
	if len(nu) != 46 {
		t.Fatalf("nuget fixture len=%d want 46", len(nu))
	}
	fired(t, `nuget = "`+nu+`"`, "NuGet API Key (oy2)", "HIGH")

	// AWS session token
	tok := "IQoJ" + "Ab3xY9zQm2Kp7Lr4Nt8Vw5Zc1Bd6Fg0Hs3Jk9Lm2Np5Qr8St1Vw4Xy7Za0Bc3De6Fg9Hj2Kl5Mn8Op1Qr4St7Vw0Xy3Za6Bc9De2Fg5Hj8Kl1Mn4Op7Qr0St3Vw6Xy9Za2Bc5De8Fg1Hj4Kl7Mn0"
	fired(t, `sessionToken = "`+tok+`"`, "AWS Session Token (IQoJ)", "HIGH")

	// Guard presisi: panjang kurang / teks biasa tidak boleh match
	notFired(t, `k = "ck_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"`, "WooCommerce API Key (ck_/cs_)")
	notFired(t, `docs: Mid-server-guide`, "Midtrans Server Key") // <12 char
	notFired(t, `xnd_development_short`, "Xendit Secret API Key")
}
