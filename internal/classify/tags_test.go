package classify

import (
	"os"
	"strings"
	"testing"
)

// Embedded files load and validate.
func TestTagsLoad(t *testing.T) {
	tg, err := Load(tagFiles, "tags")
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range tg.Validate() {
		t.Error(e)
	}

	c := tg.Counts()
	if c["name"] == 0 || c["app"] == 0 {
		t.Fatalf("tables came back empty: %v", c)
	}

	t.Logf("%d files: %v", len(tg.Files()), c)
}

func TestTagsMatchTheTables(t *testing.T) {
	tg, err := Load(tagFiles, "tags")
	if err != nil {
		t.Fatal(err)
	}

	for name, want := range byName {
		if got := tg.names[name].Category; got != want {
			t.Errorf("name %q: files say %q, the table says %q", name, got, want)
		}
	}

	for app, want := range byApp {
		if got := tg.apps[app].Category; got != want {
			t.Errorf("app %q: files say %q, the table says %q", app, got, want)
		}
	}

	for name, want := range roles {
		if got := tg.names[name].Role; got != want {
			t.Errorf("role %q: files say %q, the table says %q", name, got, want)
		}
	}

	for name, r := range tg.names {
		if _, ok := byName[name]; !ok && r.Category != "" {
			t.Errorf("name %q is categorised in %s and in no table", name, strings.Join(r.From, "+"))
		}

		if _, ok := roles[name]; !ok && r.Role != "" {
			t.Errorf("name %q has a role in %s and in no table", name, strings.Join(r.From, "+"))
		}
	}

	for app := range tg.apps {
		if _, ok := byApp[app]; !ok {
			t.Errorf("app %q is in %s and in no table", app, strings.Join(tg.apps[app].From, "+"))
		}
	}

	if n, want := len(tg.names), len(byName); n < want {
		t.Errorf("files hold %d names and table holds %d", n, want)
	}
}

// The answer Category gives, for every name either side knows.
func TestCategoryIsUnchangedByTheFiles(t *testing.T) {
	tg, err := Load(tagFiles, "tags")
	if err != nil {
		t.Fatal(err)
	}

	for name := range byName {
		was := byName[name]
		now := tg.CategoryOf(name, "", "")
		if was != now {
			t.Errorf("%q: was %q, files say %q", name, was, now)
		}
	}
}

// A key claimed twice is refused.
func TestTagsRefuseADuplicateKey(t *testing.T) {
	for _, c := range []struct {
		what  string
		files map[string]string
		want  string
	}{
		{"twice in one file array",
			map[string]string{
				"a.json": `{"category":"search","names":["mds","mds"]}`},
			"listed twice in this file"},
		{"two details about one key in one file",
			map[string]string{
				"a.json": `{"details":[{"name":"mds","about":"a","source":"x"},{"name":"mds","vendor":"Apple"}]}`},
			"listed twice in this file"},
		{"once in each of two files",
			map[string]string{
				"a.json": `{"category":"search","names":["mds"]}`,
				"b.json": `{"category":"storage","names":["mds"]}`},
			"one file to a field"},
		{"the same JSON key written twice",
			map[string]string{
				"a.json": `{"category":"search","category":"storage"}`},
			"appears twice"},
		{"two files disagreeing about one field",
			map[string]string{
				"a.json": `{"category":"search","names":["mds"]}`,
				"b.json": `{"details":[{"name":"mds","category":"storage"}]}`},
			"one file to a field"},
		{"two files disagreeing about a sentence",
			map[string]string{
				"a.json": `{"details":[{"name":"mds","about":"one thing.","source":"x"}]}`,
				"b.json": `{"details":[{"name":"mds","about":"another.","source":"y"}]}`},
			"one file to a field"},
		{"a field nobody declared",
			map[string]string{
				"a.json": `{"catgory":"search"}`},
			"unknown field"},
		{"a record naming two keys",
			map[string]string{
				"a.json": `{"details":[{"name":"a","sign":"b","about":"x","source":"y"}]}`},
			"names no key, or more than one"},
	} {
		dir := t.TempDir()
		for name, body := range c.files {
			if err := os.WriteFile(dir+"/"+name, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		_, err := Load(os.DirFS(dir), ".")
		if err == nil {
			t.Errorf("%s: loaded without complaint", c.what)
			continue
		}

		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want something about %q", c.what, err, c.want)
		}
	}
}

// File detail merges into its key.
func TestADetailSupplementsItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.json", []byte(
		`{"category":"search","names":["mds"],
		  "details":[{"name":"mds","about":"The metadata server.","source":"man mds"}]}`), 0o644)

	tg, err := Load(os.DirFS(dir), ".")
	if err != nil {
		t.Fatal(err)
	}

	r := tg.names["mds"]
	if r.Category != "search" || r.About == "" || r.Source == "" {
		t.Errorf("merged badly: %+v", r)
	}
}

// The most specific key wins field by field.
func TestOfMergesWeakestKeyFirst(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.json", []byte(`{
	  "details": [
	    {"team": "T1", "vendor": "Panic", "about": "Everything Panic ships.", "source": "panic.com"},
	    {"sign": "com.panic.Nova", "category": "developer", "about": "An editor.", "source": "panic.com/nova"},
	    {"name": "nova", "category": "media"}
	  ]}`), 0o644)

	tg, err := Load(os.DirFS(dir), ".")
	if err != nil {
		t.Fatal(err)
	}

	got := tg.Of("nova", "", "com.panic.Nova", "T1")
	if got.Vendor != "Panic" {
		t.Errorf("vendor %q, want the team's", got.Vendor)
	}

	if got.About != "An editor." || got.Source != "panic.com/nova" {
		t.Errorf("about %q from %q, want the signing id's", got.About, got.Source)
	}

	if got.Category != "developer" {
		t.Errorf("category %q, want the signing id's", got.Category)
	}

	if c := tg.Of("nova", "", "", "").Category; c != "media" {
		t.Errorf("name alone gives %q, want media", c)
	}

	if got.About != "" && got.Source == "" {
		t.Error("a sentence outlived its citation")
	}
}

// Validate fails on each thing it promises to.
func TestValidateRefusesABadRecord(t *testing.T) {
	for _, c := range []struct{ what, body, want string }{
		{"a category outside the vocabulary",
			`{"category":"banking","names":["x"]}`, "not in the vocabulary"},
		{"a role that is not one of the six",
			`{"details":[{"name":"x","role":"helper"}]}`, "not one of the six"},
		{"a sentence with no source",
			`{"details":[{"name":"x","about":"it does things."}]}`, "no source"},
		{"a record that says nothing",
			`{"details":[{"name":"x","source":"somewhere"}]}`, "says nothing"},
	} {
		dir := t.TempDir()
		os.WriteFile(dir+"/a.json", []byte(c.body), 0o644)

		tg, err := Load(os.DirFS(dir), ".")
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}

		errs := tg.Validate()
		if len(errs) == 0 {
			t.Errorf("%s: accepted", c.what)
			continue
		}

		var all []string
		for _, e := range errs {
			all = append(all, e.Error())
		}

		if !strings.Contains(strings.Join(all, "; "), c.want) {
			t.Errorf("%s: %v, want something about %q", c.what, all, c.want)
		}
	}
}
