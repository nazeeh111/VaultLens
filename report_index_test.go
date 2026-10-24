package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestHighFindingIndex(t *testing.T) {
	report, err := Audit(fixture(t), date(), false)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := Render(report, "json")
	html, err := Render(report, "html")
	if err != nil {
		t.Fatal(err)
	}
	indexEnd := bytes.Index(html, []byte("</nav>"))
	// The report-section navigation is first; inspect the findings navigation.
	start := bytes.Index(html, []byte(`<nav class="finding-index"`))
	if start < 0 {
		t.Fatal("missing high-labelled index")
	}
	indexEnd = start + bytes.Index(html[start:], []byte("</nav>"))
	index := html[start:indexEnd]
	if bytes.Count(index, []byte(`class="finding-link"`)) != 4 {
		t.Fatal("wrong high-labelled finding count")
	}
	if !bytes.Contains(index, []byte(`href="#finding-11">Shared password across records</a><code>password-reuse</code>`)) {
		t.Fatal("reuse relationship not indexed by its full-list position")
	}
	for _, ref := range []string{"item-00001", "item-00002", "item-00003"} {
		if !bytes.Contains(index, []byte(`href="#record-`+ref+`"`)) {
			t.Fatalf("missing local reference %s", ref)
		}
	}
	last := indexEnd
	for i, finding := range report.Findings {
		target := bytes.Index(html, []byte(fmt.Sprintf(`<article class="finding" id="finding-%d">`, i)))
		if target <= last {
			t.Fatalf("finding %d moved or lost", i)
		}
		end := target + bytes.Index(html[target:], []byte("</article>"))
		card := string(html[target:end])
		if !strings.Contains(card, "<h3>"+finding.Code+"</h3>") || !strings.Contains(card, finding.Explanation) {
			t.Fatalf("finding %d content changed", i)
		}
		last = target
	}
	after, _ := Render(report, "json")
	if !bytes.Equal(before, after) {
		t.Fatal("HTML render mutated report/JSON")
	}
}

func TestHighFindingIndexAbsentWithoutHigh(t *testing.T) {
	for _, findings := range [][]Finding{nil, {{Code: "review-only", Severity: "review", Items: []string{"item-00001"}}}} {
		html, err := Render(Report{Findings: findings}, "html")
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(html, []byte(`<nav class="finding-index"`)) {
			t.Fatal("empty high-labelled index")
		}
		if len(findings) == 0 && !bytes.Contains(html, []byte("No configured heuristic produced a finding")) {
			t.Fatal("empty-report explanation lost")
		}
	}
}

func TestHighFindingIndexEscapesData(t *testing.T) {
	report := Report{Findings: []Finding{{Code: `<img src=x onerror=alert(1)>`, Severity: "high", Items: []string{`item-1" onclick="alert(1)`}, Explanation: `<script>bad</script>`}}}
	html, err := Render(report, "html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(html, []byte("<img")) || bytes.Contains(html, []byte("<script>")) || bytes.Contains(html, []byte(`" onclick="`)) {
		t.Fatal("index or finding injection")
	}
	if !bytes.Contains(html, []byte("&lt;img")) || !bytes.Contains(html, []byte(`href="#finding-0"`)) {
		t.Fatal("escaped finding or stable target missing")
	}
}
