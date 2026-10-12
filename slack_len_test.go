package main

import "testing"

// ── slack-lengthening (docs resmi Slack 2016): secret 24/32/48+ ──
// Exact {24}/{32} tetap *mendeteksi* (tanpa trailing-boundary) tapi CROP secret —
// analyst tak bisa verifikasi/rotasi. Test ini mengunci capture PENUH.
func TestSlackLengthened(t *testing.T) {
	// dirakit per-bagian (hindari literal utuh memicu push-protection; nilai FAKE)
	sec52 := "9d8cfc0f596f1ed002ab5595859014e" + "567890abcdef12345678"
	full48 := "xoxb-96219857393-62330539414-22147117595-" + sec52
	fullLen := len(full48) // 92: 5+11+1+11+1+11+1+52 (secret lengthened 52)
	found := false
	for _, f := range scanContent("test://x", `tok=`+full48) {
		if f.Pattern == "Slack Bot Token (xoxb-)" {
			found = true
			if f.Match != full48 {
				t.Fatalf("xoxb crop: got %d chars, want full %d", len(f.Match), fullLen)
			}
		}
	}
	if !found {
		t.Fatalf("xoxb-48 tidak ketemu")
	}
	// klasik 24-char tetap penuh seperti dulu
	classic24 := "xoxb-19055555555-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
	fired(t, classic24, "Slack Bot Token (xoxb-)", "CRITICAL")
	// xoxp: 32 klasik penuh + 52 lengthened penuh
	sec52p := "d6bc768406e5c2e6958cfc399b438004" + "567890abcdef12345678"
	full52 := "xoxp-96219857393-62330539414-22147117595-" + sec52p
	hit32, hit52 := false, false
	for _, f := range scanContent("test://x", full52) {
		if f.Pattern == "Slack User Token (xoxp-)" {
			hit52 = true
			if f.Match != full52 {
				t.Fatalf("xoxp crop: got %d chars, want %d", len(f.Match), len(full52))
			}
		}
	}
	classic32 := "xoxp-96219857393-62330539414-22147117595-" + "d6bc768406e5c2e6958cfc399b438004"
	for _, f := range scanContent("test://x", classic32) {
		if f.Pattern == "Slack User Token (xoxp-)" {
			hit32 = true
		}
	}
	if !hit32 || !hit52 {
		t.Fatalf("xoxp klasik/lengthened: hit32=%v hit52=%v", hit32, hit52)
	}
}
