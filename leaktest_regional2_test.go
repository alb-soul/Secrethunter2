package main

import "testing"

// ── audit 2026-10-25 ronde-2: Wompi (CO) + Paystack (NG/Afrika) ──
// Nilai dirakit via konkatenasi agar tidak memicu push-protection (semua FAKE).
func TestRegionalFintechRound2(t *testing.T) {
	// Wompi (docs.wompi.co/en/docs/colombia/ambientes-y-llaves)
	wompiPrv := "prv_" + "prod_434092Xa65F54dd6a181D1f87DFa03CzS"
	wompiPrvTest := "prv_" + "test_Qw8eR7tY6uI5oP4aS3dFg7Hj9Kl2"
	fired(t, `k = "`+wompiPrv+`"`, "Wompi Private Key", "CRITICAL")
	fired(t, `k = "`+wompiPrvTest+`"`, "Wompi Private Key", "CRITICAL")

	wompiInt := "test_" + "integrity_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
	wompiEv := "prod_" + "events_4d7e2a9c1b5f8d3a6c0e4b7f2a9d1c5e"
	fired(t, `k = "`+wompiInt+`"`, "Wompi Integrity/Events Secret", "HIGH")
	fired(t, `k = "`+wompiEv+`"`, "Wompi Integrity/Events Secret", "HIGH")

	wompiPub := "pub_" + "prod_Kw4aC0rZVgLZQn209NbEKPuXLzBD28Zx"
	fired(t, `k = "`+wompiPub+`"`, "Wompi Public Key (public)", "INFO")

	// Paystack (prefix identik Stripe -> wajib konteks "paystack")
	paystackSk := "sk_" + "live_9aB3cD7eF1gH5iJ2kL8mN4oP6qR0sT"
	paystackPk := "pk_" + "test_4d7e2a9c1b5f8d3a6c0e4b7f2a9d1c5e"
	fired(t, `paystack_secret_key = "`+paystackSk+`"`, "Paystack Secret Key (context)", "HIGH")
	fired(t, `paystack_public_key = "`+paystackPk+`"`, "Paystack Public Key (context, public)", "INFO")

	// Guard: tanpa konteks "paystack" -> pola Paystack tidak boleh klaim
	notFired(t, `k = "`+paystackSk+`"`, "Paystack Secret Key (context)")
	notFired(t, `k = "prv_`+`prod_short"`, "Wompi Private Key")
}
