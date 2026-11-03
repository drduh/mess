package classify

import "testing"

func TestVendor(t *testing.T) {
	cases := []struct{ path, sign, want string }{
		{"/Users/x/bin/tool", "tool", ""},
		{"/Users/x/bin/tool", "com.example.tool", "example"},
		{"/usr/local/go/bin/go", "org.golang.go", "golang"},
		{"/opt/homebrew/Cellar/jq/1.7/bin/jq", "jq", "homebrew"},
		{"/System/Applications/Music.app/Contents/MacOS/Music",
			"com.apple.Music", "apple"},
		{"/Applications/Firefox.app/Contents/MacOS/plugin-container",
			"org.mozilla.plugincontainer", "firefox"},
	}

	for _, c := range cases {
		if got := Vendor(c.path, c.sign); got != c.want {
			t.Errorf("Vendor(%q, %q) = %q, want %q", c.path, c.sign, got, c.want)
		}
	}
}

func TestPackage(t *testing.T) {
	cases := map[string]string{
		"/nix/store/abc-git/bin/git":                       "nix",
		"/opt/homebrew/Cellar/jq/1.7/bin/jq":               "homebrew",
		"/opt/local/bin/port":                              "macports",
		"/usr/local/Cellar/node/22/bin/node":               "homebrew",
		"/usr/local/go/bin/go":                             "",
		"/Applications/Firefox.app/Contents/MacOS/firefox": "",
	}

	for path, want := range cases {
		if got := Package(path); got != want {
			t.Errorf("Package(%q) = %q, want %q", path, got, want)
		}
	}
}
