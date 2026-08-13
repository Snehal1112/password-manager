package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	gast "github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gtext "github.com/yuin/goldmark/text"
)

var (
	h1Re        = regexp.MustCompile(`(?m)^#[ \t]+(.+?)[ \t]*$`)
	codeBlockRe = regexp.MustCompile(`(?s)<pre><code(?: class="language-([\w+-]+)")?>(.*?)</code></pre>`)
	slugStrip   = regexp.MustCompile(`[^a-z0-9\s_-]`)
	slugSpace   = regexp.MustCompile(`[ \t]`)
)

// ghSlug mirrors GitHub's heading-anchor algorithm closely enough that
// existing '#some-heading' links written against the .md files on GitHub
// (including the double-hyphen an em-dash produces) keep working against
// the generated .html.
func ghSlug(s string) string {
	s = strings.ToLower(s)
	s = slugStrip.ReplaceAllString(s, "")
	return slugSpace.ReplaceAllString(s, "-")
}

// ghIDs implements goldmark/parser.IDs, generating GitHub-style slugs and
// de-duplicating collisions the same way goldmark's own default IDs type
// does (numeric suffix).
type ghIDs struct{ seen map[string]int }

func newGHIDs() *ghIDs { return &ghIDs{seen: map[string]int{}} }

func (g *ghIDs) Generate(value []byte, _ gast.NodeKind) []byte {
	slug := ghSlug(string(value))
	if slug == "" {
		slug = "section"
	}
	g.seen[slug]++
	if n := g.seen[slug]; n > 1 {
		return []byte(fmt.Sprintf("%s-%d", slug, n-1))
	}
	return []byte(slug)
}

func (g *ghIDs) Put(value []byte) { g.seen[string(value)]++ }

func headingText(n gast.Node, source []byte) string {
	var buf bytes.Buffer
	_ = gast.Walk(n, func(node gast.Node, entering bool) (gast.WalkStatus, error) {
		if entering {
			if t, ok := node.(*gast.Text); ok {
				buf.Write(t.Segment.Value(source))
			}
		}
		return gast.WalkContinue, nil
	})
	return buf.String()
}

// wrapCodeBlocks turns goldmark's bare <pre><code class="language-x">...
// output into the codewrap/code-hd/copy-btn chrome docs-theme.css and
// doc-theme.js expect, matching the fenced code cards in admin-manual.html.
func wrapCodeBlocks(html string) string {
	return codeBlockRe.ReplaceAllStringFunc(html, func(m string) string {
		sub := codeBlockRe.FindStringSubmatch(m)
		lang := sub[1]
		if lang == "" {
			lang = "text"
		}
		body := sub[2]
		return `<div class="codewrap"><div class="code-hd"><span class="code-lang">` + lang +
			`</span><button class="copy-btn">Copy</button></div><pre class="code with-hd">` + body + `</pre></div>`
	})
}

type tocItem struct {
	ID   string
	Text string
}

const pageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>%[1]s — RocketVault Docs</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="%[2]s"/>
</head>
<body>
<header class="doc-header">
  <a class="doc-back" href="%[3]s">&larr; Admin Manual</a>
  <div class="doc-brand">
    <div class="doc-mark" aria-hidden="true"></div>
    <span class="doc-kicker">RocketVault Docs</span>
  </div>
  <h1 class="doc-title">%[1]s</h1>
  <div class="doc-meta"><span class="doc-chip">%[4]s</span></div>
  <hr/>
</header>
%[5]s
<main class="doc">
%[6]s
</main>
<footer class="doc-footer"><a href="%[3]s">&larr; Back to the Admin Manual</a></footer>
<script src="%[7]s"></script>
</body>
</html>
`

func renderDoc(e docEntry) error {
	srcPath := filepath.Join(repoRoot, e.Src)
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	body := string(raw)

	title := filepath.Base(e.Src)
	if m := h1Re.FindStringSubmatchIndex(body); m != nil {
		title = body[m[2]:m[3]]
		body = body[:m[0]] + body[m[1]:]
	}

	md := goldmark.New(
		goldmark.WithExtensions(extension.Table),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	)

	source := []byte(body)
	ctx := parser.NewContext(parser.WithIDs(newGHIDs()))
	doc := md.Parser().Parse(gtext.NewReader(source), parser.WithContext(ctx))

	var toc []tocItem
	hasOwnTOC := false
	_ = gast.Walk(doc, func(n gast.Node, entering bool) (gast.WalkStatus, error) {
		if entering {
			if h, ok := n.(*gast.Heading); ok && h.Level == 2 {
				id := ""
				if v, ok := h.AttributeString("id"); ok {
					if b, ok := v.([]byte); ok {
						id = string(b)
					}
				}
				text := headingText(h, source)
				if strings.EqualFold(strings.TrimSpace(text), "table of contents") {
					hasOwnTOC = true
				}
				toc = append(toc, tocItem{ID: id, Text: text})
			}
		}
		return gast.WalkContinue, nil
	})

	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, source, doc); err != nil {
		return err
	}
	bodyHTML := wrapCodeBlocks(buf.String())

	tocHTML := ""
	if len(toc) >= 3 && !hasOwnTOC {
		var links strings.Builder
		for _, t := range toc {
			links.WriteString(`<li><a href="#` + t.ID + `">` + t.Text + `</a></li>`)
		}
		tocHTML = `<nav class="doc-toc"><div class="doc-toc-label">On this page</div><ol>` + links.String() + `</ol></nav>`
	}

	outPath := filepath.Join(repoRoot, e.Out)
	outDir := filepath.Dir(outPath)
	cssHref, err := filepath.Rel(outDir, assetsCSS)
	if err != nil {
		return err
	}
	jsHref, err := filepath.Rel(outDir, assetsJS)
	if err != nil {
		return err
	}
	backHref, err := filepath.Rel(outDir, adminManual)
	if err != nil {
		return err
	}

	page := fmt.Sprintf(pageTemplate, title, cssHref, backHref, e.Src, tocHTML, bodyHTML, jsHref)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(page), 0o644); err != nil {
		return err
	}
	fmt.Println("built", e.Out)
	return nil
}

func buildDocs() error {
	for _, e := range docsList {
		if err := renderDoc(e); err != nil {
			return fmt.Errorf("%s: %w", e.Src, err)
		}
	}
	return nil
}
