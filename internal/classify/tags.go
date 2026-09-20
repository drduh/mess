package classify

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

type Record struct {
	Team     string   `json:"team,omitempty"`
	Sign     string   `json:"sign,omitempty"`
	App      string   `json:"app,omitempty"`
	Name     string   `json:"name,omitempty"`
	Category string   `json:"category,omitempty"`
	Role     string   `json:"role,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	About    string   `json:"about,omitempty"`
	Source   string   `json:"source,omitempty"`
	From     []string `json:"-"`
}

type File struct {
	About    string   `json:"about,omitempty"`
	Category string   `json:"category,omitempty"`
	Teams    []string `json:"teams,omitempty"`
	Signs    []string `json:"signs,omitempty"`
	Apps     []string `json:"apps,omitempty"`
	Names    []string `json:"names,omitempty"`
	Details  []Record `json:"details,omitempty"`
}

type Tags struct {
	files    []string
	teams    map[string]Record
	signs    map[string]Record
	apps     map[string]Record
	names    map[string]Record
	catName  map[string]string
	catApp   map[string]string
	catSign  map[string]string
	roleName map[string]string
}

//go:embed tags/*.json
var tagFiles embed.FS

var tags = func() *Tags {
	t, err := Load(tagFiles, "tags")
	if err != nil {
		panic("classify: tag files did not load: " + err.Error())
	}

	return t
}()

func TagNotes() map[string]Note { return tags.Notes() }

func Load(fsys fs.FS, dir string) (*Tags, error) {
	names, err := fs.Glob(fsys, path.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	t := &Tags{
		teams: map[string]Record{}, signs: map[string]Record{},
		apps: map[string]Record{}, names: map[string]Record{},
	}

	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		short := path.Base(name)

		f, err := decodeFile(b, short)
		if err != nil {
			return nil, err
		}

		if err := t.add(f, short); err != nil {
			return nil, err
		}
		t.files = append(t.files, short)
	}
	t.index()

	return t, nil
}

func (t *Tags) index() {
	narrow := func(m map[string]Record, pick func(Record) string) map[string]string {
		out := make(map[string]string, len(m))
		for k, r := range m {
			if v := pick(r); v != "" {
				out[k] = v
			}
		}
		return out
	}
	cat := func(r Record) string { return r.Category }
	t.catName = narrow(t.names, cat)
	t.catApp = narrow(t.apps, cat)
	t.catSign = narrow(t.signs, cat)
	t.roleName = narrow(t.names, func(r Record) string { return r.Role })
}

func decodeFile(b []byte, name string) (File, error) {
	var f File

	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("%s: %w", name, err)
	}

	if _, err := dec.Token(); err != io.EOF {
		return f, fmt.Errorf("%s: more than one JSON value in the file", name)
	}

	if err := dupInObject(b, name); err != nil {
		return f, err
	}

	return f, nil
}

func dupInObject(b []byte, file string) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))

	type frame struct {
		object bool
		key    bool
		seen   map[string]bool
	}

	var stack []frame
	done := func() {
		if n := len(stack) - 1; n >= 0 && stack[n].object {
			stack[n].key = true
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{object: true, key: true, seen: map[string]bool{}})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				done()
			}
		default:
			n := len(stack) - 1
			if n >= 0 && stack[n].object && stack[n].key {
				s, _ := v.(string)
				if stack[n].seen[s] {
					return fmt.Errorf("%s: %q appears twice in the same object", file, s)
				}
				stack[n].seen[s] = true
				stack[n].key = false
				continue
			}
			done()
		}
	}
}

func (t *Tags) add(f File, file string) error {
	mine := map[string]bool{}

	claim := func(space, key string) error {
		if mine[space+"\x00"+key] {
			return fmt.Errorf("%s: %s %q is listed twice in this file", file, space, key)
		}
		mine[space+"\x00"+key] = true

		return nil
	}

	put := func(space string, m map[string]Record, r Record) error {
		key := r.key()
		if key == "" {
			return fmt.Errorf("%s: a record names no key", file)
		}

		r.From = []string{file}
		if old, ok := m[key]; ok {
			merged, err := supplement(old, r)
			if err != nil {
				return fmt.Errorf("%s: %s %q: %w", file, space, key, err)
			}

			m[key] = merged
			return nil
		}

		m[key] = r
		return nil
	}

	for _, list := range []struct {
		space string
		keys  []string
		m     map[string]Record
		set   func(*Record, string)
	}{
		{"team", f.Teams, t.teams, func(r *Record, k string) { r.Team = k }},
		{"sign", f.Signs, t.signs, func(r *Record, k string) { r.Sign = k }},
		{"app", f.Apps, t.apps, func(r *Record, k string) { r.App = k }},
		{"name", f.Names, t.names, func(r *Record, k string) { r.Name = k }},
	} {
		for _, k := range list.keys {
			if err := claim(list.space, k); err != nil {
				return err
			}
			r := Record{Category: f.Category}
			list.set(&r, k)
			if err := put(list.space, list.m, r); err != nil {
				return err
			}
		}
	}

	for _, r := range f.Details {
		if r.Category == "" {
			r.Category = f.Category
		}

		space, m := t.spaceOf(r)
		if m == nil {
			return fmt.Errorf("%s: a record names no key, or more than one", file)
		}

		if err := claim("detail "+space, r.key()); err != nil {
			return err
		}

		if err := put(space, m, r); err != nil {
			return err
		}
	}

	return nil
}

func (r Record) key() string {
	switch {
	case r.Sign != "":
		return r.Sign
	case r.Team != "":
		return r.Team
	case r.App != "":
		return r.App
	case r.Name != "":
		return r.Name
	}
	return ""
}

func (t *Tags) spaceOf(r Record) (string, map[string]Record) {
	n := 0
	for _, s := range []string{r.Team, r.Sign, r.App, r.Name} {
		if s != "" {
			n++
		}
	}

	if n != 1 {
		return "", nil
	}

	switch {
	case r.Sign != "":
		return "sign", t.signs
	case r.Team != "":
		return "team", t.teams
	case r.App != "":
		return "app", t.apps
	}

	return "name", t.names
}

func supplement(a, b Record) (Record, error) {
	clash := func(field, was, now string) error {
		return fmt.Errorf("%s is %q in %s and %q here; one file to a field",
			field, was, strings.Join(a.From, ", "), now)
	}

	for _, f := range []struct{ name, was, now string }{
		{"category", a.Category, b.Category},
		{"role", a.Role, b.Role},
		{"vendor", a.Vendor, b.Vendor},
		{"about", a.About, b.About},
	} {
		if f.was != "" && f.now != "" && f.was != f.now {
			return a, clash(f.name, f.was, f.now)
		}
	}

	return merge(a, b), nil
}

func merge(a, b Record) Record {
	if b.Category != "" {
		a.Category = b.Category
	}

	if b.Role != "" {
		a.Role = b.Role
	}

	if b.Vendor != "" {
		a.Vendor = b.Vendor
	}

	if b.About != "" {
		a.About = b.About
		a.Source = b.Source
	}

	if b.About == "" && b.Source != "" {
		a.Source = b.Source
	}

	for _, f := range b.From {
		if !contains(a.From, f) {
			a.From = append(a.From, f)
		}
	}

	return a
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (t *Tags) Of(name, app, sign, team string) Record {
	if t == nil {
		return Record{}
	}

	var out Record

	for _, look := range []struct {
		m   map[string]Record
		key string
	}{
		{t.names, name}, {t.apps, app}, {t.teams, team}, {t.signs, sign},
	} {
		if look.key == "" {
			continue
		}
		if r, ok := look.m[look.key]; ok {
			out = merge(out, r)
		}
	}

	return out
}

func (t *Tags) CategoryOf(name, app, sign string) string {
	if t == nil {
		return ""
	}

	if sign != "" {
		if c, ok := t.catSign[sign]; ok {
			return c
		}
	}

	if app != "" {
		if c, ok := t.catApp[app]; ok {
			return c
		}
	}

	if name != "" {
		if c, ok := t.catName[name]; ok {
			return c
		}
	}

	return ""
}

func (t *Tags) RoleOf(name string) string {
	if t == nil {
		return ""
	}

	return t.roleName[name]
}

func (t *Tags) Validate() []error {
	var out []error
	known := map[string]bool{}
	for _, c := range Vocabulary {
		known[c.Name] = true
	}

	roleNames := map[string]bool{
		RoleInit: true, RoleStub: true, RoleShell: true,
		RoleInterpreter: true, RoleNetwork: true, RolePrivilege: true,
	}

	for _, m := range []map[string]Record{t.signs, t.teams, t.apps, t.names} {
		for key, r := range m {
			where := fmt.Sprintf("%s: %q", strings.Join(r.From, "+"), key)

			if r.Category != "" && !known[r.Category] {
				out = append(out, fmt.Errorf("%s: category %q is not in the vocabulary", where, r.Category))
			}

			if r.Role != "" && !roleNames[r.Role] {
				out = append(out, fmt.Errorf("%s: role %q is not one of the six", where, r.Role))
			}

			if len(r.About) > 240 {
				out = append(out, fmt.Errorf("%s: about is %d characters, and the limit is 240", where, len(r.About)))
			}

			if r.About != "" && r.Source == "" {
				out = append(out, fmt.Errorf("%s: about with no source; say where the claim came from", where))
			}

			if r.Category == "" && r.Role == "" && r.About == "" && r.Vendor == "" {
				out = append(out, fmt.Errorf("%s: the record says nothing", where))
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Error() < out[j].Error() })

	return out
}

func (t *Tags) Counts() map[string]int {
	if t == nil {
		return map[string]int{}
	}

	return map[string]int{
		"sign": len(t.signs), "team": len(t.teams),
		"app": len(t.apps), "name": len(t.names),
	}
}

func (t *Tags) Files() []string { return append([]string(nil), t.files...) }

type Note struct {
	About  string `json:"about"`
	Source string `json:"source"`
	Vendor string `json:"vendor,omitempty"`
	From   string `json:"from"`
}

func (t *Tags) Notes() map[string]Note {
	out := map[string]Note{}

	if t == nil {
		return out
	}

	for space, m := range map[string]map[string]Record{
		"sign": t.signs, "team": t.teams, "app": t.apps, "name": t.names,
	} {
		for key, r := range m {
			if r.About == "" && r.Vendor == "" {
				continue
			}
			out[space+":"+key] = Note{
				About: r.About, Source: r.Source, Vendor: r.Vendor,
				From: strings.Join(r.From, ", "),
			}
		}
	}

	return out
}

func (t *Tags) Labels() (byRole, byCategory map[string]string) {
	byRole, byCategory = map[string]string{}, map[string]string{}
	if t == nil {
		return
	}

	for k, v := range t.roleName {
		byRole[k] = v
	}

	for k, v := range t.catName {
		byCategory[k] = v
	}

	return byRole, byCategory
}
