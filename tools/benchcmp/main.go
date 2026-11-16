// benchcmp menilai output JSON secrethunter2 terhadap truth file gencorpus.
//
//	benchcmp -truth corpus.jsonl.truth.tsv -findings out.json [-text out.txt] [-v]
//
// Metrik:
//
//	TP found/planted  — secret tertanam yang terdeteksi (URL sama, nilai cocok)
//	FP trap           — temuan pada URL /trap/ (jebakan false positive)
//	FP fill           — temuan pada URL /fill/ (filler bersih)
//	FP out-of-scope   — temuan pada host di luar scope
//	extra on TP       — temuan lain di record TP yang bukan nilai tertanam
//	bad text lines    — baris -o (mode teks) yang tidak berformat `[SEV] Nama | nilai | url`
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type finding struct {
	URL      string `json:"url"`
	Pattern  string `json:"pattern"`
	Match    string `json:"match"`
	Severity string `json:"severity"`
}

type truth struct{ url, family, value string }

func related(match, value string) bool {
	if match == value || strings.Contains(match, value) {
		return true
	}
	if strings.Contains(value, match) && float64(len(match)) >= 0.6*float64(len(value)) {
		return true
	}
	return false
}

var reLine = regexp.MustCompile(`^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\] [^|]+ \| .+ \| \S+$`)

func main() {
	truthPath := flag.String("truth", "", "truth tsv dari gencorpus")
	findPath := flag.String("findings", "", "output --json secrethunter2")
	textPath := flag.String("text", "", "output teks -o (opsional, cek format baris)")
	verbose := flag.Bool("v", false, "tampilkan detail FP & TP yang terlewat")
	flag.Parse()

	var truths []truth
	tf, err := os.Open(*truthPath)
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(tf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 3)
		if len(p) == 3 {
			// nilai multi-baris (PEM) ditulis apa adanya → tsv memotong di \n;
			// gabungkan baris lanjutan tidak dibutuhkan karena value hanya header+1 baris
			truths = append(truths, truth{p[0], p[1], p[2]})
		} else if len(truths) > 0 && len(p) == 1 {
			truths[len(truths)-1].value += "\n" + p[0]
		}
	}
	tf.Close()

	raw, err := os.ReadFile(*findPath)
	if err != nil {
		panic(err)
	}
	var fds []finding
	if err := json.Unmarshal(raw, &fds); err != nil {
		panic(err)
	}

	byURL := map[string][]finding{}
	for _, f := range fds {
		byURL[f.URL] = append(byURL[f.URL], f)
	}

	found, foundHigh := 0, 0
	famTotal, famFound := map[string]int{}, map[string]int{}
	var missed []truth
	used := map[*finding]bool{}
	for _, t := range truths {
		famTotal[t.family]++
		ok, high := false, false
		list := byURL[t.url]
		for i := range list {
			if related(list[i].Match, t.value) {
				ok = true
				used[&list[i]] = true
				if list[i].Severity == "CRITICAL" || list[i].Severity == "HIGH" {
					high = true
				}
			}
		}
		if high {
			foundHigh++
		}
		if ok {
			found++
			famFound[t.family]++
		} else {
			missed = append(missed, t)
		}
	}

	var fpTrap, fpFill, fpOOS, extraTP []finding
	for u, list := range byURL {
		for i := range list {
			f := list[i]
			switch {
			case !strings.Contains(u, ".target.test/"):
				fpOOS = append(fpOOS, f)
			case strings.Contains(u, "/trap/"):
				fpTrap = append(fpTrap, f)
			case strings.Contains(u, "/fill/"):
				fpFill = append(fpFill, f)
			case strings.Contains(u, "/tp/") && !used[&list[i]]:
				extraTP = append(extraTP, f)
			}
		}
	}

	sev := map[string]int{}
	for _, f := range fds {
		sev[f.Severity]++
	}

	fmt.Printf("findings total     : %d  (C=%d H=%d M=%d L=%d I=%d)\n", len(fds), sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"], sev["INFO"])
	fmt.Printf("TP found/planted   : %d/%d (%.1f%%)\n", found, len(truths), 100*float64(found)/float64(max(1, len(truths))))
	fmt.Printf("TP as HIGH/CRIT    : %d\n", foundHigh)
	fmt.Printf("FP trap            : %d\n", len(fpTrap))
	fmt.Printf("FP fill            : %d\n", len(fpFill))
	fmt.Printf("FP out-of-scope    : %d\n", len(fpOOS))
	fmt.Printf("extra on TP records: %d\n", len(extraTP))

	if *textPath != "" {
		tfh, err := os.Open(*textPath)
		if err == nil {
			s := bufio.NewScanner(tfh)
			s.Buffer(make([]byte, 1<<20), 16<<20)
			bad, total := 0, 0
			for s.Scan() {
				total++
				if !reLine.MatchString(s.Text()) {
					bad++
				}
			}
			tfh.Close()
			fmt.Printf("text lines (bad)   : %d (%d)\n", total, bad)
		}
	}

	var fams []string
	for k := range famTotal {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	fmt.Println("per family (found/planted):")
	for _, k := range fams {
		mark := ""
		if famFound[k] < famTotal[k] {
			mark = "  <-- miss"
		}
		fmt.Printf("  %-26s %d/%d%s\n", k, famFound[k], famTotal[k], mark)
	}
	if *verbose {
		show := func(title string, l []finding) {
			byPat := map[string]int{}
			for _, f := range l {
				byPat[f.Severity+" "+f.Pattern]++
			}
			var ps []string
			for k := range byPat {
				ps = append(ps, k)
			}
			sort.Slice(ps, func(i, j int) bool { return byPat[ps[i]] > byPat[ps[j]] })
			fmt.Printf("── %s per pola:\n", title)
			for _, k := range ps {
				fmt.Printf("   %4dx %s\n", byPat[k], k)
			}
			agg := map[string]int{}
			for _, f := range l {
				m := f.Match
				if len(m) > 60 {
					m = m[:60] + "…"
				}
				agg[f.Severity+" "+f.Pattern+" | "+m]++
			}
			var ks []string
			for k := range agg {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			fmt.Printf("── %s (%d)\n", title, len(l))
			for i, k := range ks {
				if i >= 40 {
					fmt.Printf("   … %d lagi\n", len(ks)-i)
					break
				}
				fmt.Printf("   %3dx %s\n", agg[k], k)
			}
		}
		show("FP trap", fpTrap)
		show("FP fill", fpFill)
		show("FP out-of-scope", fpOOS)
		show("extra on TP", extraTP)
		fmt.Printf("── missed TP (%d)\n", len(missed))
		agg := map[string]int{}
		for _, t := range missed {
			v := t.value
			if len(v) > 50 {
				v = v[:50] + "…"
			}
			agg[t.family+" | "+strings.ReplaceAll(v, "\n", `\n`)]++
		}
		var ks []string
		for k := range agg {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for i, k := range ks {
			if i >= 40 {
				break
			}
			fmt.Printf("   %3dx %s\n", agg[k], k)
		}
	}
}
