package main

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

type docPage struct {
	Slug, Label, Group, Key string
	Title, Description      string
	Body                    template.HTML
	Sections                []docSection
}

type docSection struct {
	ID, Title string
	Children  []docSection
}

func (p docPage) URL() string {
	if p.Slug == "ethos" {
		return "/docs/"
	}
	return "/docs/" + p.Slug + "/"
}

func docsTask(args []string) error {
	check := len(args) == 1 && args[0] == "--check"
	if len(args) > 0 && !check {
		return fmt.Errorf("usage: go run ./dev docs [--check]")
	}
	pages := []docPage{
		{Slug: "ethos", Label: "ethos", Group: "begin", Key: "e"},
		{Slug: "getting-started", Label: "getting started", Group: "begin", Key: "s"},
		{Slug: "rex", Label: "rex support", Group: "use", Key: "r"},
		{Slug: "cli", Label: "cli usage", Group: "use", Key: "c"},
		{Slug: "self-hosting", Label: "self-hosting", Group: "operate", Key: "h"},
		{Slug: "setups", Label: "setups", Group: "operate", Key: "u"},
	}
	tmpl, err := template.ParseFiles("docs/layout.html")
	if err != nil {
		return err
	}
	md := goldmark.New(goldmark.WithExtensions(extension.Table), goldmark.WithParserOptions(parser.WithAutoHeadingID()))
	for i := range pages {
		p := &pages[i]
		source, err := os.ReadFile(filepath.Join("docs", p.Slug+".md"))
		if err != nil {
			return err
		}
		doc := md.Parser().Parse(text.NewReader(source))
		for node := doc.FirstChild(); node != nil; node = node.NextSibling() {
			if heading, ok := node.(*ast.Heading); ok {
				label := string(heading.Text(source))
				id, _ := heading.AttributeString("id")
				section := docSection{ID: string(id.([]byte)), Title: label}
				switch heading.Level {
				case 1:
					p.Title = label
				case 2:
					p.Sections = append(p.Sections, section)
				case 3:
					parent := &p.Sections[len(p.Sections)-1]
					parent.Children = append(parent.Children, section)
				}
			}
			if paragraph, ok := node.(*ast.Paragraph); ok && p.Description == "" {
				p.Description = string(paragraph.Text(source))
			}
		}
		var body bytes.Buffer
		if err := md.Renderer().Render(&body, source, doc); err != nil {
			return err
		}
		// Only our repository's Markdown is rendered. Goldmark leaves raw HTML disabled.
		p.Body = template.HTML(body.String())
		if err := writeDoc(filepath.Join("site", "docs", p.Slug+".md"), source, check); err != nil {
			return err
		}
	}
	for i, p := range pages {
		var previous, next *docPage
		if i > 0 {
			previous = &pages[i-1]
		}
		if i+1 < len(pages) {
			next = &pages[i+1]
		}
		data := struct {
			Page           docPage
			Pages          []docPage
			Groups         []string
			Previous, Next *docPage
		}{p, pages, []string{"begin", "use", "operate"}, previous, next}
		var output bytes.Buffer
		if err := tmpl.Execute(&output, data); err != nil {
			return err
		}
		path := filepath.Join("site", strings.TrimPrefix(p.URL(), "/"), "index.html")
		if err := writeDoc(path, output.Bytes(), check); err != nil {
			return err
		}
	}
	fmt.Println("docs: six pages and their Markdown sources are up to date")
	return nil
}

func writeDoc(path string, content []byte, check bool) error {
	if check {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, content) {
			return fmt.Errorf("%s is stale; run go run ./dev docs", path)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}
