package main

// engine.go — prefilter Aho-Corasick + windowed regex (audit 2026-11b).
//
// Masalah lama: 483 pola × (body + varian decode), setiap pola yang lolos gate
// menjalankan NFA regexp Go atas SELURUH body (±0.5 MB/s per core). Gate lama
// juga lemah: literal minimal 4 char tanpa ekspansi, sehingga 57 pola tanpa gate
// sama sekali (mis. `A(?:KIA|SIA…)` setelah faktorisasi prefix parser, atau
// `api[_-]?key` yang hanya menghasilkan "api").
//
// Desain baru:
//  1. Literal wajib per pola diekstrak dari AST dengan aljabar "exact set" ala
//     prefilter RE2: rangkaian potongan berhingga dikalikan
//     (`api[_-]?key` → {apikey, api_key, api-key}), min 2 char (case-sensitive)
//     / 3 char (case-insensitive). Hasilnya DNF: AND antar-group, OR di dalam.
//  2. Semua literal dari semua pola dicari dalam SATU pass Aho-Corasick atas
//     body (lowercase ASCII on-the-fly; literal case-sensitive diverifikasi byte
//     per byte). Pola yang salah satu group-nya tidak muncul → dilewati.
//  3. Pola yang lolos dijalankan hanya pada JENDELA di sekitar kemunculan
//     literal group paling jarang: [occ-L-2, occ+len+L+2], L = panjang match
//     maksimum (byte) dari AST. Bagian tak-berhingga (`+`, `*`, `{n,}`) dihitung
//     sebagai runCap dan tepi jendela diperluas menembus run karakter yang bisa
//     dimakan bagian tak-berhingga itu, sehingga token panjang tidak terpotong.
//     Bila literal terlalu padat (jendela > 50% body) → fallback full scan.
//
// Kesetaraan dengan full scan diuji di engine_test.go (corpus + semua sampel
// test) dan bisa dimatikan dengan --no-window.

import (
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	minExactLit   = 2        // literal case-sensitive minimum
	minFoldLit    = 3        // literal case-insensitive minimum
	maxExactSet   = 64       // ukuran maksimum himpunan string hasil perkalian
	maxLitLen     = 32       // literal dipotong ke prefix (tetap sound)
	runCap        = 256      // byte yang diasumsikan untuk tiap repetisi tak-berhingga
	maxWindowL    = 64 << 10 // L di atas ini → pola tidak di-window
	occCap        = 8192     // kemunculan per literal yang dicatat; lebih = "padat"
	windowMergeGp = 256      // jendela berjarak < ini digabung
	extendCap     = 1 << 20  // batas perluasan tepi jendela menembus run
)

// noWindowGlobal (--no-window) memaksa full scan untuk setiap pola yang lolos gate.
var noWindowGlobal bool

// ─── 1. Ekstraksi literal wajib ───────────────────────────────────────────────

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// product mengalikan dua himpunan string; nil bila hasil > maxExactSet.
func product(a, b []string) []string {
	if len(a)*len(b) > maxExactSet {
		return nil
	}
	out := make([]string, 0, len(a)*len(b))
	seen := make(map[string]struct{}, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			s := x + y
			if len(s) > maxLitLen {
				s = s[:maxLitLen]
			}
			if _, d := seen[s]; !d {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// asciiLower: lowercase HANYA A-Z (panjang byte tetap) — harus identik dengan
// normalisasi yang dipakai acAuto.find atas body.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func lowerAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = asciiLower(s)
	}
	return out
}

// exactOf mengembalikan himpunan berhingga kecil semua string yang bisa
// dicocokkan subtree (ok=false bila tak berhingga / terlalu besar).
// fold=true: string di-lowercase dan harus dicari case-insensitive.
func exactOf(re *syntax.Regexp) (strs []string, fold bool, ok bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, false, true
	case syntax.OpLiteral:
		s := string(re.Rune)
		if re.Flags&syntax.FoldCase != 0 {
			if !isASCIIString(s) {
				return nil, false, false
			}
			return []string{asciiLower(s)}, true, true
		}
		return []string{s}, false, true
	case syntax.OpCharClass:
		n := 0
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			n += int(hi-lo) + 1
			if n > 10 || hi >= utf8.RuneSelf {
				return nil, false, false
			}
			for r := lo; r <= hi; r++ {
				out = append(out, string(r))
			}
		}
		if len(out) == 0 {
			return nil, false, false
		}
		return out, false, true
	case syntax.OpCapture:
		return exactOf(re.Sub[0])
	case syntax.OpQuest:
		s, f, ok := exactOf(re.Sub[0])
		if !ok {
			return nil, false, false
		}
		return append(append([]string{}, s...), ""), f, true
	case syntax.OpRepeat:
		if re.Max < 0 || re.Max > 4 {
			return nil, false, false
		}
		s, f, ok := exactOf(re.Sub[0])
		if !ok {
			return nil, false, false
		}
		cur := []string{""}
		for i := 0; i < re.Max; i++ {
			step := s
			if i >= re.Min {
				step = append(append([]string{}, s...), "")
			}
			if cur = product(cur, step); cur == nil {
				return nil, false, false
			}
		}
		return cur, f, true
	case syntax.OpConcat:
		cur, fold := []string{""}, false
		for _, sub := range re.Sub {
			s, f, ok := exactOf(sub)
			if !ok {
				return nil, false, false
			}
			if f && !fold {
				cur, fold = lowerAll(cur), true
			}
			if fold && !f {
				s = lowerAll(s)
			}
			if cur = product(cur, s); cur == nil {
				return nil, false, false
			}
		}
		return cur, fold, true
	case syntax.OpAlternate:
		var all []string
		fold := false
		for _, sub := range re.Sub {
			s, f, ok := exactOf(sub)
			if !ok {
				return nil, false, false
			}
			fold = fold || f
			all = append(all, s...)
			if len(all) > maxExactSet {
				return nil, false, false
			}
		}
		if fold {
			all = lowerAll(all)
		}
		return dedupStrings(all), fold, true
	}
	return nil, false, false
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := ss[:0:0]
	for _, s := range ss {
		if _, d := seen[s]; !d {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// groupFromSet: himpunan string → satu group OR, nil bila ada string yang
// terlalu pendek (gate tidak selektif / tidak sound untuk string kosong).
func groupFromSet(ss []string, fold bool) litGroup {
	if len(ss) == 0 || len(ss) > maxExactSet {
		return nil
	}
	minL := minExactLit
	if fold {
		minL = minFoldLit
	}
	ss = dedupStrings(ss)
	for _, s := range ss {
		if len(s) < minL {
			return nil
		}
	}
	// himpunan minimal: string yang memuat anggota lain redundan
	// ({apikey, apikey"} → {apikey}: setiap kemunculan `apikey"` memuat `apikey`)
	g := make(litGroup, 0, len(ss))
	for i, s := range ss {
		redundant := false
		for j, t := range ss {
			if i != j && len(t) < len(s) && strings.Contains(s, t) {
				redundant = true
				break
			}
		}
		if !redundant {
			g = append(g, needLit{lit: s, fold: fold})
		}
	}
	sort.Slice(g, func(i, j int) bool { return g[i].lit < g[j].lit })
	return g
}

func groupScore(g litGroup) int { // makin besar makin selektif
	m := 1 << 30
	for _, l := range g {
		if len(l.lit) < m {
			m = len(l.lit)
		}
	}
	return m*100 - len(g)
}

type elemSet struct {
	strs []string
	fold bool
}

// repeatElemSet: untuk `x+` / `x{n,…}` (n≥1) dengan x himpunan kecil berhingga,
// kembalikan himpunan satu salinan x.
func repeatElemSet(re *syntax.Regexp) (elemSet, bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if !(re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && re.Min >= 1)) {
		return elemSet{}, false
	}
	s, f, ok := exactOf(re.Sub[0])
	if !ok {
		return elemSet{}, false
	}
	for _, x := range s {
		if x == "" {
			return elemSet{}, false
		}
	}
	return elemSet{s, f}, true
}

// requiredGroups mengembalikan group literal yang HARUS terpenuhi setiap match.
func requiredGroups(re *syntax.Regexp) []litGroup {
	if s, f, ok := exactOf(re); ok {
		if g := groupFromSet(s, f); g != nil {
			return []litGroup{g}
		}
		return nil
	}
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return requiredGroups(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredGroups(re.Sub[0])
		}
	case syntax.OpConcat:
		var out []litGroup
		run, runFold, active := []string{""}, false, false
		flush := func() {
			if active {
				if g := groupFromSet(run, runFold); g != nil {
					out = append(out, g)
				}
			}
			run, runFold, active = []string{""}, false, false
		}
		for _, sub := range re.Sub {
			if s, f, ok := exactOf(sub); ok {
				if f && !runFold {
					run, runFold = lowerAll(run), true
				}
				if runFold && !f {
					s = lowerAll(s)
				}
				p := product(run, s)
				if p == nil { // terlalu besar: tutup run, mulai run baru dari s
					flush()
					if f {
						runFold = true
					}
					p = s
				}
				run, active = p, true
				continue
			}
			// repetisi min≥1 atas himpunan kecil (`[0-9]{12,20}`, `[a-f]+`): match
			// pasti diawali satu salinan elemen → perpanjang run (prefix), dan
			// diakhiri satu salinan → mulai run baru (suffix). Contoh
			// `/[0-9]{12,}:` → {"/0".."/9"} dan {"0:".."9:"}.
			if rep, ok := repeatElemSet(sub); ok {
				if active {
					s, f := rep.strs, rep.fold
					if runFold && !f {
						s = lowerAll(s)
					} else if f && !runFold {
						run, runFold = lowerAll(run), true
					}
					if p := product(run, s); p != nil {
						run = p
					}
				}
				flush()
				run, runFold, active = rep.strs, rep.fold, true
				continue
			}
			flush()
			out = append(out, requiredGroups(sub)...)
		}
		flush()
		return out
	case syntax.OpAlternate:
		var union litGroup
		seen := map[needLit]bool{}
		for _, sub := range re.Sub {
			gs := requiredGroups(sub)
			if len(gs) == 0 {
				return nil
			}
			best := gs[0]
			for _, g := range gs[1:] {
				if groupScore(g) > groupScore(best) {
					best = g
				}
			}
			for _, l := range best {
				if !seen[l] {
					seen[l] = true
					union = append(union, l)
				}
			}
		}
		if len(union) == 0 || len(union) > maxExactSet {
			return nil
		}
		sort.Slice(union, func(i, j int) bool { return union[i].lit < union[j].lit })
		return []litGroup{union}
	}
	return nil
}

// ─── 2. Panjang match maksimum & himpunan byte run tak-berhingga ─────────────

// markBytes menandai semua byte yang bisa dikonsumsi subtree.
func markBytes(re *syntax.Regexp, set *[256]bool) {
	markRange := func(lo, hi rune) {
		for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
			set[r] = true
		}
		if hi >= utf8.RuneSelf {
			for b := 0x80; b < 256; b++ {
				set[b] = true
			}
		}
	}
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				// semua varian case + fold Unicode (K Kelvin, ſ) → byte non-ASCII
				for _, v := range []rune{r, []rune(strings.ToLower(string(r)))[0], []rune(strings.ToUpper(string(r)))[0]} {
					markRange(v, v)
				}
				markRange(utf8.RuneSelf, utf8.MaxRune)
				continue
			}
			markRange(r, r)
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			markRange(re.Rune[i], re.Rune[i+1])
		}
	case syntax.OpAnyChar:
		markRange(0, utf8.MaxRune)
	case syntax.OpAnyCharNotNL:
		markRange(0, '\n'-1)
		markRange('\n'+1, utf8.MaxRune)
	default:
		for _, s := range re.Sub {
			markBytes(s, set)
		}
	}
}

// maxLenOf mengembalikan panjang match maksimum dalam byte. Repetisi
// tak-berhingga dihitung (Min+runCap)× dan byte-nya ditandai di unb.
func maxLenOf(re *syntax.Regexp, unb *[256]bool, nUnb *int) int {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return 3 * len(re.Rune) // K (Kelvin) = 3 byte
		}
		n := 0
		for _, r := range re.Rune {
			n += utf8.RuneLen(r)
		}
		return n
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0
		}
		return utf8.RuneLen(re.Rune[len(re.Rune)-1])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxLenOf(re.Sub[0], unb, nUnb)
	case syntax.OpStar, syntax.OpPlus:
		*nUnb++
		markBytes(re.Sub[0], unb)
		return (1 + runCap) * maxLenOf(re.Sub[0], unb, nUnb)
	case syntax.OpRepeat:
		n := maxLenOf(re.Sub[0], unb, nUnb)
		if re.Max < 0 {
			*nUnb++
			markBytes(re.Sub[0], unb)
			return (re.Min + runCap) * n
		}
		return re.Max * n
	case syntax.OpConcat:
		t := 0
		for _, s := range re.Sub {
			t += maxLenOf(s, unb, nUnb)
		}
		return t
	case syntax.OpAlternate:
		m := 0
		for _, s := range re.Sub {
			if n := maxLenOf(s, unb, nUnb); n > m {
				m = n
			}
		}
		return m
	}
	return 0
}

// ─── 3. Aho-Corasick ─────────────────────────────────────────────────────────

type acAuto struct {
	classes [256]uint8
	nclass  int
	next    []int32   // state*nclass + class
	out     [][]int32 // state → id literal-lowercase yang berakhir di sini
	lowLits []string
	vars    [][]int32 // id literal-lowercase → id varian (needLit)
}

func buildAC(lows []string, vars [][]int32) *acAuto {
	a := &acAuto{lowLits: lows, vars: vars}
	// kompresi alfabet: hanya byte yang muncul di literal yang punya kelas
	cls := 1
	for _, s := range lows {
		for i := 0; i < len(s); i++ {
			if a.classes[s[i]] == 0 {
				a.classes[s[i]] = uint8(cls)
				cls++
			}
		}
	}
	a.nclass = cls
	// trie
	type node struct{ child map[uint8]int32 }
	nodes := []node{{child: map[uint8]int32{}}}
	outs := [][]int32{nil}
	for id, s := range lows {
		cur := int32(0)
		for i := 0; i < len(s); i++ {
			c := a.classes[s[i]]
			nx, ok := nodes[cur].child[c]
			if !ok {
				nx = int32(len(nodes))
				nodes = append(nodes, node{child: map[uint8]int32{}})
				outs = append(outs, nil)
				nodes[cur].child[c] = nx
			}
			cur = nx
		}
		outs[cur] = append(outs[cur], int32(id))
	}
	n := len(nodes)
	a.next = make([]int32, n*a.nclass)
	fail := make([]int32, n)
	queue := make([]int32, 0, n)
	for c := 0; c < a.nclass; c++ {
		if nx, ok := nodes[0].child[uint8(c)]; ok && c != 0 {
			a.next[c] = nx
			fail[nx] = 0
			queue = append(queue, nx)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		st := queue[qi]
		outs[st] = append(outs[st], outs[fail[st]]...)
		for c := 1; c < a.nclass; c++ {
			if nx, ok := nodes[st].child[uint8(c)]; ok {
				fail[nx] = a.next[int(fail[st])*a.nclass+c]
				a.next[int(st)*a.nclass+c] = nx
				queue = append(queue, nx)
			} else {
				a.next[int(st)*a.nclass+c] = a.next[int(fail[st])*a.nclass+c]
			}
		}
	}
	a.out = outs
	return a
}

// occTable: posisi awal kemunculan per varian literal (dipakai ulang via pool).
type occTable struct {
	pos     [][]int32
	count   []int32
	touched []int32
}

var occPool = sync.Pool{New: func() any {
	return &occTable{pos: make([][]int32, len(engLits)), count: make([]int32, len(engLits))}
}}

func (o *occTable) release() {
	for _, v := range o.touched {
		o.pos[v] = o.pos[v][:0]
		o.count[v] = 0
	}
	o.touched = o.touched[:0]
	occPool.Put(o)
}

func (a *acAuto) find(content string) *occTable {
	o := occPool.Get().(*occTable)
	st := 0
	nc := a.nclass
	for i := 0; i < len(content); i++ {
		c := content[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		st = int(a.next[st*nc+int(a.classes[c])])
		outs := a.out[st]
		if outs == nil {
			continue
		}
		for _, lid := range outs {
			ln := len(a.lowLits[lid])
			start := i - ln + 1
			for _, vid := range a.vars[lid] {
				v := engLits[vid]
				if !v.fold && content[start:start+ln] != v.lit {
					continue
				}
				if o.count[vid] == 0 {
					o.touched = append(o.touched, vid)
				}
				o.count[vid]++
				if o.count[vid] <= occCap {
					o.pos[vid] = append(o.pos[vid], int32(start))
				}
			}
		}
	}
	return o
}

// ─── 4. Registry per pola ────────────────────────────────────────────────────

type patEngine struct {
	groups [][]int32 // AND → OR id varian
	L      int       // panjang match maks (byte); -1 = tidak bisa di-window
	nUnb   int       // jumlah repetisi tak-berhingga
	unb    [256]bool
	pre    func(string) bool // prefilter khusus (pola tanpa literal); nil = tidak ada
}

// prePgpass: baris .pgpass = host:port:db:user:pass. Cek murah per baris:
// sebelum ':' ke-4 hanya boleh ada karakter field .pgpass [A-Za-z0-9._*-].
func prePgpass(content string) bool {
	colons, ok := 0, true
	for i := 0; i < len(content); i++ {
		c := content[i]
		if c == '\n' {
			colons, ok = 0, true
			continue
		}
		if !ok {
			continue
		}
		switch {
		case c == ':':
			if colons++; colons >= 4 {
				return true
			}
		case isAlnumByte(c) || c == '.' || c == '_' || c == '-' || c == '*':
		default:
			ok = false
		}
	}
	return false
}

var (
	engLits []needLit
	engPats []patEngine
	engAC   *acAuto
)

func buildEngine() {
	idx := map[needLit]int32{}
	engLits = engLits[:0]
	engPats = make([]patEngine, len(patterns))
	for pi, p := range patterns {
		re, err := syntax.Parse(p.Regex.String(), syntax.Perl)
		pe := &engPats[pi]
		if err != nil {
			pe.L = -1
			continue
		}
		for _, g := range requiredGroups(re) {
			var ids []int32
			for _, l := range g {
				id, ok := idx[l]
				if !ok {
					id = int32(len(engLits))
					idx[l] = id
					engLits = append(engLits, l)
				}
				ids = append(ids, id)
			}
			pe.groups = append(pe.groups, ids)
		}
		pe.L = maxLenOf(re, &pe.unb, &pe.nUnb)
		if pe.L > maxWindowL {
			pe.L = -1
		}
		if p.Name == "PostgreSQL .pgpass entry" {
			pe.pre = prePgpass
		}
	}
	// literal lowercase unik → varian
	lowIdx := map[string]int32{}
	var lows []string
	var vars [][]int32
	for vid, l := range engLits {
		k := asciiLower(l.lit)
		id, ok := lowIdx[k]
		if !ok {
			id = int32(len(lows))
			lowIdx[k] = id
			lows = append(lows, k)
			vars = append(vars, nil)
		}
		vars[id] = append(vars[id], int32(vid))
	}
	engAC = buildAC(lows, vars)
	occPool = sync.Pool{New: func() any {
		return &occTable{pos: make([][]int32, len(engLits)), count: make([]int32, len(engLits))}
	}}
}

// ─── 5. Kandidat per pola ────────────────────────────────────────────────────

type window struct{ s, e int }

// patternWindows: (skip=true) pola pasti tidak match; (full=true) jalankan atas
// seluruh body; selain itu daftar jendela.
func patternWindows(pi int, content string, occ *occTable) (wins []window, skip, full bool) {
	pe := &engPats[pi]
	if pe.pre != nil && !pe.pre(content) {
		return nil, true, false
	}
	if len(pe.groups) == 0 {
		return nil, false, true
	}
	best, bestN := -1, int32(1<<30)
	for gi, g := range pe.groups {
		var n int32
		for _, v := range g {
			n += occ.count[v]
		}
		if n == 0 {
			return nil, true, false
		}
		if n < bestN {
			best, bestN = gi, n
		}
	}
	if noWindowGlobal || pe.L < 0 || bestN > occCap || int64(bestN)*int64(2*pe.L) > int64(len(content))*4 {
		return nil, false, true
	}
	var starts []int32
	maxLit := 0
	for _, v := range pe.groups[best] {
		starts = append(starts, occ.pos[v]...)
		if n := len(engLits[v].lit); n > maxLit {
			maxLit = n
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	n := len(content)
	pad := pe.L + 2
	for _, o := range starts {
		s, e := int(o)-pad, int(o)+maxLit+pad
		if s < 0 {
			s = 0
		}
		if e > n {
			e = n
		}
		if len(wins) > 0 && s <= wins[len(wins)-1].e+windowMergeGp {
			if e > wins[len(wins)-1].e {
				wins[len(wins)-1].e = e
			}
			continue
		}
		wins = append(wins, window{s, e})
	}
	if pe.nUnb > 0 {
		// Tembus run karakter yang bisa dimakan repetisi tak-berhingga supaya
		// token/run panjang (mis. JWT dengan payload 3 KB) tidak terpotong tepi
		// jendela. Setelah menembus satu run, tambah margin L (bagian berhingga
		// sesudahnya) lalu ulangi — maksimal sebanyak jumlah repetisi
		// tak-berhingga di pola (satu match tidak bisa melewati lebih banyak run).
		for i := range wins {
			w := &wins[i]
			for it := 0; it < pe.nUnb && w.s > 0; it++ {
				moved := false
				for k := 0; w.s > 0 && pe.unb[content[w.s-1]] && k < extendCap; k++ {
					w.s--
					moved = true
				}
				if !moved && it > 0 {
					break
				}
				if w.s -= pe.L; w.s < 0 {
					w.s = 0
				}
			}
			if w.s >= 2 {
				w.s -= 2
			} else {
				w.s = 0
			}
			for it := 0; it < pe.nUnb && w.e < n; it++ {
				moved := false
				for k := 0; w.e < n && pe.unb[content[w.e]] && k < extendCap; k++ {
					w.e++
					moved = true
				}
				if !moved && it > 0 {
					break
				}
				if w.e += pe.L; w.e > n {
					w.e = n
				}
			}
			if w.e+2 <= n {
				w.e += 2
			} else {
				w.e = n
			}
		}
		// gabung ulang setelah perluasan
		merged := wins[:0]
		for _, w := range wins {
			if len(merged) > 0 && w.s <= merged[len(merged)-1].e {
				if w.e > merged[len(merged)-1].e {
					merged[len(merged)-1].e = w.e
				}
				continue
			}
			merged = append(merged, w)
		}
		wins = merged
	}
	covered := 0
	for _, w := range wins {
		covered += w.e - w.s
	}
	if covered*2 > n {
		return nil, false, true
	}
	return wins, false, false
}

// patternCandidates menjalankan regex pola pi (full / per jendela) dan
// menambahkan kandidat mentah (sebelum guard pasca-regex) ke out.
func patternCandidates(pi int, content string, occ *occTable, out []patternCandidate) []patternCandidate {
	wins, skip, full := patternWindows(pi, content, occ)
	if skip {
		return out
	}
	p := &patterns[pi]
	add := func(loc []int, off, ws, we int) {
		s, e := loc[0], loc[1]
		if p.MatchGroup > 0 {
			gi := 2 * p.MatchGroup
			if gi+1 >= len(loc) || loc[gi] < 0 {
				return
			}
			s, e = loc[gi], loc[gi+1]
		}
		// match yang menempel di tepi jendela (bukan tepi body) bisa artefak
		// konteks terpotong (\b, ^, $) → buang; match asli tidak pernah di sana.
		if ws > 0 && loc[0] < 2 {
			return
		}
		if we < len(content) && loc[1] > we-off-2 {
			return
		}
		if e > s {
			out = append(out, patternCandidate{pi: pi, startPos: s + off, endPos: e + off})
		}
	}
	if full {
		for _, loc := range p.Regex.FindAllStringSubmatchIndex(content, -1) {
			add(loc, 0, 0, len(content))
		}
		return out
	}
	for _, w := range wins {
		for _, loc := range p.Regex.FindAllStringSubmatchIndex(content[w.s:w.e], -1) {
			add(loc, w.s, w.s, w.e)
		}
	}
	return out
}
