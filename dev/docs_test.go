package main

import "testing"

// A direct Pages upload must serve the same Markdown as the rendered pages.
func TestPublishedDocsMatchSources(t *testing.T) {
	t.Chdir("..")
	if err := docsTask([]string{"--check"}); err != nil {
		t.Fatal(err)
	}
}
