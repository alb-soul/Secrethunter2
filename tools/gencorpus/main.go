// gencorpus membangkitkan corpus uji JSONL ala `httpx -json -irr` untuk
// membandingkan output secrethunter2 sebelum/sesudah perubahan.
//
// Semua kredensial DIBANGKITKAN saat runtime (seed deterministik) dan bersifat
// DUMMY: formatnya valid, nilainya acak — tidak ada string key literal di repo
// (aman dari GitHub push protection / secret scanning).
//
// Output:
//
//	<out>             JSONL (url,status_code,body,header,raw_header,content_type)
//	<out>.truth.tsv   daftar nilai yang SENGAJA ditanam (TP) per URL
//
// URL berpola:
//
//	https://<host>.<scope>/tp/...    record berisi secret yang wajib terdeteksi
//	https://<host>.<scope>/trap/...  record jebakan FP (temuan apa pun = FP)
//	https://<host>.<scope>/fill/...  filler realistis (tanpa secret)
//	https://other.example/...        di luar scope (harus dibuang --scope)
//
// Pemakaian:
//
//	go run ./tools/gencorpus -o /tmp/corpus.jsonl -n 1500 -big 3
//	go run ./tools/gencorpus -o /tmp/oversize.jsonl -n 50 -oversize
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	alnum   = upper + lower + digits
	hexL    = "0123456789abcdef"
	b32     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b64     = alnum + "+/"
	b64url  = alnum + "-_"
	lowAlnm = lower + digits
)

var rng *rand.Rand

// rs: string acak dari charset, dijamin campuran (tidak terlihat seperti
// placeholder / identifier) supaya TP memang "secret-like".
func rs(cs string, n int) string {
	for {
		b := make([]byte, n)
		for i := range b {
			b[i] = cs[rng.Intn(len(cs))]
		}
		s := string(b)
		if !looksPlaceholder(s) {
			return s
		}
	}
}

// looksPlaceholder: tolak sampel acak yang kebetulan memuat kata placeholder
// (secrethunter2 benar menolaknya, tapi itu bukan yang ingin diukur di TP).
func looksPlaceholder(s string) bool {
	l := strings.ToLower(s)
	for _, w := range []string{"xxx", "yyy", "zzz", "aaaa", "test", "exampl", "dummy", "sampl", "none", "null",
		"todo", "asdf", "qwer", "redact", "string", "lorem", "fixme", "replace", "insert", "your", "placeh", "abc123", "undef", "0000", "1111"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func uuid() string {
	return rs(hexL, 8) + "-" + rs(hexL, 4) + "-4" + rs(hexL, 3) + "-a" + rs(hexL, 3) + "-" + rs(hexL, 12)
}

func b64url64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func jwt(payload string) string {
	h := b64url64(`{"alg":"HS256","typ":"JWT"}`)
	return h + "." + b64url64(payload) + "." + rs(b64url, 43)
}

type plant struct {
	family  string // nama keluarga (bebas, hanya untuk laporan)
	snippet string // potongan konten yang ditanam
	value   string // nilai yang diharapkan muncul di kolom ke-2 output
}

// tpGenerators: setiap fungsi menghasilkan satu secret DUMMY berformat valid
// beserta konteks khas tempat ia biasa bocor (config JS, .env, header, dsb.).
var tpGenerators = []func() plant{
	func() plant { v := "AKIA" + rs(b32, 16); return plant{"aws-key-id", `{accessKeyId:"` + v + `"}`, v} },
	func() plant {
		v := rs(b64, 40)
		return plant{"aws-secret", `aws_secret_access_key = "` + v + `"`, v}
	},
	func() plant {
		v := rs(b64, 40)
		return plant{"aws-secret-sdk-ctx", `new S3Client({credentials:{region:"us-east-1",secretAccessKey:"` + v + `"}})`, v}
	},
	func() plant { v := "ghp_" + rs(alnum, 36); return plant{"github-pat", `const t="` + v + `";`, v} },
	func() plant {
		v := "github_pat_" + rs(alnum, 22) + "_" + rs(alnum, 59)
		return plant{"github-fg-pat", `GH_TOKEN=` + v + "\n", v}
	},
	func() plant { v := "glpat-" + rs(alnum, 20); return plant{"gitlab-pat", `"token":"` + v + `"`, v} },
	func() plant {
		v := "xoxb-" + rs(digits, 12) + "-" + rs(digits, 12) + "-" + rs(alnum, 24)
		return plant{"slack-bot", `slack:{token:"` + v + `"}`, v}
	},
	func() plant {
		v := "sk_live_51" + rs(alnum, 97)
		return plant{"stripe-live", `stripeSecret:"` + v + `"`, v}
	},
	func() plant { v := "AIza" + rs(b64url, 35); return plant{"google-api", `key:"` + v + `"`, v} },
	func() plant {
		v := "sk-proj-" + rs(b64url, 74) + "T3BlbkFJ" + rs(b64url, 74)
		return plant{"openai-proj", `OPENAI_API_KEY="` + v + `"`, v}
	},
	func() plant {
		v := "sk-ant-api03-" + rs(b64url, 93) + "AA"
		return plant{"anthropic", `x-api-key: ` + v + "\n", v}
	},
	func() plant {
		v := "SG." + rs(b64url, 22) + "." + rs(b64url, 43)
		return plant{"sendgrid", `sendgrid_key='` + v + `'`, v}
	},
	func() plant {
		v := rs(digits[1:], 1) + rs(digits, 9) + ":AA" + rs(b64url, 33)
		return plant{"telegram-bot", `fetch("https://api.telegram.org/bot` + v + `/sendMessage")`, v}
	},
	func() plant {
		v := "https://discord.com/api/webhooks/" + rs(digits, 18) + "/" + rs(b64url, 68)
		return plant{"discord-webhook", `hook="` + v + `"`, v}
	},
	func() plant {
		v := "https://hooks.slack.com/services/T" + rs(upper+digits, 10) + "/B" + rs(upper+digits, 10) + "/" + rs(alnum, 24)
		return plant{"slack-webhook", `url: '` + v + `'`, v}
	},
	func() plant {
		v := "mongodb+srv://svc_" + rs(lower, 5) + ":" + rs(alnum, 14) + "@cluster0." + rs(lowAlnm, 6) + ".mongodb.net/prod"
		return plant{"mongo-uri", `MONGO_URL="` + v + `"`, v}
	},
	func() plant {
		v := "postgres://app:" + rs(alnum, 16) + "@db." + rs(lower, 6) + ".internal:5432/app"
		return plant{"postgres-uri", `DATABASE_URL=` + v + "\n", v}
	},
	func() plant {
		body := rs(b64, 64) + "\n" + rs(b64, 64) + "\n" + rs(b64, 40)
		v := "-----BEGIN RSA PRIVATE KEY-----\n" + body[:64]
		return plant{"rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n", v}
	},
	func() plant {
		v := jwt(`{"iss":"supabase","ref":"` + rs(lower, 20) + `","role":"service_role","iat":1700000000,"exp":2000000000}`)
		return plant{"supabase-service-role", `createClient(url,"` + v + `")`, v}
	},
	func() plant {
		v := rs(b64url[:62]+"_~.", 3) + "8Q~" + rs(b64url[:62]+"_~.", 34)
		return plant{"azure-ad-secret", `"clientSecret": "` + v + `"`, v}
	},
	func() plant { v := "hf_" + rs(upper+lower, 34); return plant{"huggingface", `HF_TOKEN=` + v + "\n", v} },
	func() plant {
		v := "GOCSPX-" + rs(b64url, 28)
		return plant{"google-oauth-secret", `client_secret: "` + v + `"`, v}
	},
	func() plant { v := "dop_v1_" + rs(hexL, 64); return plant{"digitalocean", `DO_TOKEN="` + v + `"`, v} },
	func() plant {
		v := "shpat_" + rs(hexL, 32)
		return plant{"shopify", `X-Shopify-Access-Token: ` + v + "\n", v}
	},
	func() plant {
		v := "npm_" + rs(alnum, 36)
		return plant{"npm", `//registry.npmjs.org/:_authToken=` + v + "\n", v}
	},
	func() plant {
		v := "sk-ant-oat01-" + rs(b64url, 93) + "AA"
		return plant{"anthropic-oauth", `CLAUDE_CODE_OAUTH_TOKEN=` + v + "\n", v}
	},
	func() plant {
		v := "sk-admin-" + rs(b64url, 140)
		return plant{"openai-admin", `const k = "` + v + `";`, v}
	},
	func() plant {
		v := "AQ." + rs(b64url, 50)
		return plant{"gemini-vertex-express", `GOOGLE_API_KEY="` + v + `"`, v}
	},
	func() plant {
		v := "cfat_" + rs(alnum, 40) + rs(hexL, 8)
		return plant{"cloudflare-cfat", `CF_API_TOKEN=` + v + "\n", v}
	},
	func() plant {
		v := "A21AA" + rs(b64url, 92)
		return plant{"paypal-bearer", `Authorization: "Bearer ` + v + `"`, v}
	},
}

// trapGenerators: konten yang SEHARUSNYA tidak menghasilkan temuan (FP traps).
var trapGenerators = []func() string{
	// AWS-ish huruf kecil di identifier minified
	func() string { return `var akia` + rs(lowAlnm, 16) + `=function(){return 1};` },
	// connection string tanpa kredensial / placeholder
	func() string { return `const MONGO="mongodb://localhost:27017/` + rs(lower, 6) + `";` },
	func() string { return `DATABASE_URL=postgres://user:password@localhost:5432/dev` + "\n" },
	// identifier snake/kebab case yang kebetulan berprefiks token
	func() string { return `function re_render_component_` + rs(lower, 6) + `_lifecycle(){}` },
	func() string {
		return `<div class="pa-` + rs(lower, 6) + `-container-wrapper-element-responsive-layout-grid-item">`
	},
	func() string { return `x.rnd_seed_value_generator_for_tests_only=` + rs(digits, 3) + `;` },
	// hash / UUID / base64 acak tanpa konteks
	func() string { return `"integrity":"sha512-` + rs(b64, 86) + `=="` },
	func() string { return `"etag":"` + rs(hexL, 40) + `","id":"` + uuid() + `"` },
	func() string { return `data:image/png;base64,` + rs(b64, 600) },
	func() string { return `"sourcesContent":"` + rs(b64, 300) + `"` },
	// placeholder resmi dokumentasi
	func() string { return `aws_access_key_id = AKIAIOSFODNN7EXAMPLE` + "\n" },
	// dirakit saat runtime: literal placeholder pun diblokir GitHub push protection
	func() string { return `stripe.api_key = "sk_` + "live_" + strings.Repeat("x", 24) + `"` },
	func() string { return `token: "ghp_` + strings.Repeat("0", 36) + `"` },
	// timestamp:hash mirip Telegram
	func() string { return `t=` + rs(digits, 10) + `:` + rs(hexL, 35) },
	// Basic yang bukan user:pass
	func() string {
		return `authorization: Basic ` + base64.StdEncoding.EncodeToString([]byte(rs(alnum, 18)))
	},
	// oauth: diikuti identifier panjang (bukan Twitch token)
	func() string { return `{oauth:handleOauthCallbackRedirectUri,state:s}` },
	// Mailgun/Mailchimp-ish di dalam kata lain
	func() string { return `monkey-` + rs(lowAlnm, 32) + ` hotkey-` + rs(lowAlnm, 32) },
}

func fillerJS(n int) string {
	var b strings.Builder
	words := []string{"render", "state", "props", "useEffect", "dispatch", "handler", "module", "exports", "return", "function", "const", "value", "items", "length", "push", "map", "filter", "reduce", "Promise", "resolve", "then", "catch", "fetch", "json"}
	for b.Len() < n {
		w := words[rng.Intn(len(words))]
		switch rng.Intn(7) {
		case 0:
			fmt.Fprintf(&b, "function %s%s(e,t){return e.%s(t)}", w, rs(upper, 1), words[rng.Intn(len(words))])
		case 1:
			fmt.Fprintf(&b, "var %s=%d;", rs(lower, 2), rng.Intn(100000))
		case 2:
			fmt.Fprintf(&b, `"%s":"%s",`, w, rs(lower, 8))
		case 3:
			fmt.Fprintf(&b, "%s.%s(%s,{%s:!0});", rs(lower, 1), w, rs(lower, 1), words[rng.Intn(len(words))])
		case 4:
			fmt.Fprintf(&b, `t.exports={id:"%s",v:"%d.%d.%d"};`, uuid(), rng.Intn(9), rng.Intn(20), rng.Intn(50))
		case 5:
			b.WriteString("\n")
		default:
			fmt.Fprintf(&b, "if(%s&&%s.%s)throw new Error(\"%s failed\");", rs(lower, 1), rs(lower, 1), w, w)
		}
	}
	return b.String()
}

func fillerHTML(n int, cjk bool) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Shop</title></head><body>")
	for b.Len() < n {
		if cjk {
			b.WriteString("<p>商品の説明です。送料無料でお届けします。お問い合わせはこちらへ。新しいアカウントを作成してください。</p>")
		} else {
			b.WriteString("<p>Lorem shop item description, free shipping. Contact support for help.</p>")
		}
	}
	return b.String()
}

type rec struct {
	URL         string            `json:"url"`
	StatusCode  int               `json:"status_code"`
	Body        string            `json:"body,omitempty"`
	Header      map[string]string `json:"header,omitempty"`
	RawHeader   string            `json:"raw_header,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

func main() {
	out := flag.String("o", "corpus.jsonl", "output JSONL")
	n := flag.Int("n", 1500, "jumlah record normal")
	big := flag.Int("big", 3, "jumlah body besar (5-10 MB)")
	oversize := flag.Bool("oversize", false, "sisipkan satu baris > 64 MB di tengah file")
	scope := flag.String("scope", "target.test", "domain scope")
	seed := flag.Int64("seed", 20261116, "seed RNG")
	flag.Parse()
	rng = rand.New(rand.NewSource(*seed))

	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()
	tf, err := os.Create(*out + ".truth.tsv")
	if err != nil {
		panic(err)
	}
	defer tf.Close()
	tw := bufio.NewWriter(tf)
	defer tw.Flush()

	enc := json.NewEncoder(w)
	write := func(r rec) {
		if err := enc.Encode(r); err != nil {
			panic(err)
		}
	}
	host := func() string { return rs(lower, 5) + "." + *scope }
	stdHdr := func(ct string) string {
		return "HTTP/1.1 200 OK\r\nContent-Type: " + ct + "\r\nServer: nginx\r\nX-Request-Id: " + uuid() + "\r\n\r\n"
	}
	planted := 0
	tp := func(u string, p plant) {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", u, p.family, p.value)
		planted++
	}

	for i := 0; i < *n; i++ {
		switch i % 10 {
		case 0, 1, 2: // TP JS bundle
			u := fmt.Sprintf("https://%s/tp/js/app.%d.js", host(), i)
			var parts []string
			for k := 0; k < 1+rng.Intn(2); k++ {
				p := tpGenerators[(i/10*3+k+i)%len(tpGenerators)]()
				tp(u, p)
				parts = append(parts, p.snippet)
			}
			body := fillerJS(2000+rng.Intn(30000)) + "\n" + strings.Join(parts, ";\n") + "\n" + fillerJS(2000+rng.Intn(20000))
			write(rec{URL: u, StatusCode: 200, Body: body, RawHeader: stdHdr("application/javascript"), ContentType: "application/javascript"})
		case 3: // TP di header (hanya map `header`, tanpa raw_header)
			u := fmt.Sprintf("https://%s/tp/hdr/%d", host(), i)
			v := "ghp_" + rs(alnum, 36)
			tp(u, plant{"github-pat-header-map", "", v})
			write(rec{URL: u, StatusCode: 200, Body: `{"ok":true}`, Header: map[string]string{"content_type": "application/json", "x_debug_token": v}, ContentType: "application/json"})
		case 4: // TP di halaman CJK (UTF-8 multibyte dominan)
			u := fmt.Sprintf("https://%s/tp/cjk/%d", host(), i)
			p := tpGenerators[i%len(tpGenerators)]()
			tp(u, p)
			body := fillerHTML(20000, true) + "<script>" + p.snippet + "</script>" + fillerHTML(5000, true)
			write(rec{URL: u, StatusCode: 200, Body: body, RawHeader: stdHdr("text/html; charset=utf-8"), ContentType: "text/html"})
		case 5, 6: // FP traps
			u := fmt.Sprintf("https://%s/trap/%d.js", host(), i)
			var parts []string
			for k := 0; k < 3; k++ {
				parts = append(parts, trapGenerators[(i+k*7)%len(trapGenerators)]())
			}
			body := fillerJS(3000+rng.Intn(20000)) + "\n" + strings.Join(parts, "\n") + "\n" + fillerJS(3000)
			write(rec{URL: u, StatusCode: 200, Body: body, RawHeader: stdHdr("application/javascript"), ContentType: "application/javascript"})
		case 7: // biner (gambar) — body hasil string(bytes) seperti httpx
			u := fmt.Sprintf("https://%s/fill/img/%d.png", host(), i)
			raw := make([]byte, 20000)
			rng.Read(raw)
			write(rec{URL: u, StatusCode: 200, Body: "\x89PNG\r\n" + string(raw), RawHeader: stdHdr("image/png"), ContentType: "image/png"})
		case 8: // out of scope (punya secret, harus dibuang --scope)
			u := fmt.Sprintf("https://cdn.other.example/oos/%d.js", i)
			body := fillerJS(5000) + `const t="ghp_` + rs(alnum, 36) + `";`
			write(rec{URL: u, StatusCode: 200, Body: body, RawHeader: stdHdr("application/javascript"), ContentType: "application/javascript"})
		default: // filler HTML/JS bersih
			u := fmt.Sprintf("https://%s/fill/%d", host(), i)
			write(rec{URL: u, StatusCode: 200, Body: fillerHTML(3000+rng.Intn(20000), false) + "<script>" + fillerJS(5000) + "</script>", RawHeader: stdHdr("text/html"), ContentType: "text/html"})
		}
		if *oversize && i == *n/2 {
			// satu record > 64 MB (body JS raksasa) lalu record TP sesudahnya
			u := fmt.Sprintf("https://%s/fill/huge.js", host())
			write(rec{URL: u, StatusCode: 200, Body: fillerJS(70 << 20), ContentType: "application/javascript"})
			u2 := fmt.Sprintf("https://%s/tp/after-oversize.js", host())
			p := tpGenerators[0]()
			tp(u2, p)
			write(rec{URL: u2, StatusCode: 200, Body: fillerJS(4000) + p.snippet, ContentType: "application/javascript"})
		}
	}
	for i := 0; i < *big; i++ {
		u := fmt.Sprintf("https://%s/tp/big/vendor.%d.js", host(), i)
		size := (5 + rng.Intn(5)) << 20
		var b strings.Builder
		b.WriteString(fillerJS(size / 3))
		for k := 0; k < 2; k++ {
			p := tpGenerators[(i*5+k)%len(tpGenerators)]()
			tp(u, p)
			b.WriteString(";" + p.snippet + ";")
			b.WriteString(fillerJS(size / 3))
		}
		write(rec{URL: u, StatusCode: 200, Body: b.String(), RawHeader: stdHdr("application/javascript"), ContentType: "application/javascript"})
	}
	fmt.Fprintf(os.Stderr, "gencorpus: %d record normal + %d big, %d secret ditanam → %s\n", *n, *big, planted, *out)
}
