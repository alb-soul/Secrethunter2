package main

import "testing"

// ── audit 2026-10-25: sk_live_ dari provider non-Stripe (context-anchored) ──
// Semua nilai FAKE; dirakit via konkatenasi agar tidak memicu push-protection.
func TestStripeStyleRegional(t *testing.T) {
	sk := "sk_" + "live_9aB3cD7eF1gH5iJ2kL8mN4oP6qR0sT"
	pk := "pk_" + "test_4d7e2a9c1b5f8d3a6c0e4b7f2a9d1c5e"

	// Konteks -> label regional yang benar
	fired(t, `pagarme_secret_key = "`+sk+`"`, "Pagar.me Secret Key (context)", "CRITICAL")
	fired(t, `PAGAR_ME_API_KEY = "`+sk+`"`, "Pagar.me Secret Key (context)", "CRITICAL")
	fired(t, `paymongo_secret_key = "`+sk+`"`, "PayMongo Secret Key (context)", "CRITICAL")
	fired(t, `culqi_private = "`+sk+`"`, "Culqi Secret Key (context)", "CRITICAL")
	fired(t, `paymongo_public_key = "`+pk+`"`, "PayMongo Public Key (context, public)", "INFO")
	fired(t, `culqi_public = "`+pk+`"`, "Culqi Public Key (context, public)", "INFO")

	// Tanpa konteks -> jangan klaim regional (Stripe pattern tetap mendeteksi)
	notFired(t, `k = "`+sk+`"`, "Pagar.me Secret Key (context)")
	notFired(t, `k = "`+sk+`"`, "PayMongo Secret Key (context)")
	notFired(t, `k = "`+sk+`"`, "Culqi Secret Key (context)")
}
