package main

import "testing"

// ── audit 2026-10-25: layanan khas per wilayah ──
// Nilai dirakit per-bagian agar tidak memicu push-protection GitHub (semua FAKE).
func TestRegionalFintech2026(t *testing.T) {
	// Flutterwave (Afrika)
	fwSec := "FLW" + "SECK-3f9a2c7e1b8d4a6f0c5e2b9d7a1f3c8e-X"
	fwTest := "FLW" + "SECK_TEST-8b2e4f6a1c3d5e7f9a0b2c4d6e8f1a3b-X"
	fwPub := "FLW" + "PUBK-4d7e2a9c1b5f8d3a6c0e4b7f2a9d1c5e-X"
	fired(t, `k = "`+fwSec+`"`, "Flutterwave Secret Key (FLWSECK...)", "CRITICAL")
	fired(t, `k = "`+fwTest+`"`, "Flutterwave Secret Key (FLWSECK...)", "CRITICAL")
	fired(t, `k = "`+fwPub+`"`, "Flutterwave Public Key (FLWPUBK...)", "INFO")

	// Mercado Pago (LatAm)
	mp := "APP" + "_USR-1234567890123456-102615-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c-123456789"
	fired(t, `token = "`+mp+`"`, "Mercado Pago Credential (APP_USR-)", "MEDIUM")

	// Omise / Opn (Thailand/SEA)
	omSec := "skey_" + "test_52jyu0r8mim84ylp454"
	omLive := "skey_" + "5x9k2m7q4t8w1n6r3b0c"
	omPub := "pkey_" + "test_52jyu0r8o4307z0zz00"
	fired(t, `sk = "`+omSec+`"`, "Omise Secret Key", "CRITICAL")
	fired(t, `sk = "`+omLive+`"`, "Omise Secret Key", "CRITICAL")
	fired(t, `pk = "`+omPub+`"`, "Omise Public Key (public)", "INFO")

	// Toss Payments (Korea)
	tossSec := "test_" + "sk_9aB3cD7eF1gH5iJ2kL8mN4oP6qR0sT"
	tossGsk := "live_" + "gsk_4d7e2a9c1b5f8d3a6c0e4b7f2a9d1c5e"
	tossCk := "test_" + "ck_9aB3cD7eF1gH5iJ2kL8mN4oP6qR0sT"
	fired(t, `sk = "`+tossSec+`"`, "Toss Payments Secret Key", "CRITICAL")
	fired(t, `sk = "`+tossGsk+`"`, "Toss Payments Secret Key", "CRITICAL")
	fired(t, `ck = "`+tossCk+`"`, "Toss Payments Client Key (public)", "INFO")

	// Guard presisi (terlalu pendek / bukan key)
	notFired(t, `sk = "skey_test_short"`, "Omise Secret Key")
	notFired(t, `sk = "test_sk_abc"`, "Toss Payments Secret Key")
	notFired(t, `k = "FLW`+`SECK-short-X"`, "Flutterwave Secret Key (FLWSECK...)")
	notFired(t, `token = "APP`+`_USR-abc"`, "Mercado Pago Credential (APP_USR-)")
}
