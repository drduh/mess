package classify

import "strings"

type Bundle struct {
	Name string `json:"name"`
	Ext  string `json:"ext"`
	Path string `json:"path"`
}

var bundleExts = map[string]string{
	"app":             "app",
	"xpc":             "XPC service",
	"appex":           "app extension",
	"framework":       "framework",
	"bundle":          "bundle",
	"systemextension": "system extension",
	"kext":            "kernel extension",
	"plugin":          "plug-in",
	"pluginkit":       "plug-in",
	"service":         "service",
	"prefPane":        "preference pane",
	"qlgenerator":     "Quick Look generator",
	"mdimporter":      "Spotlight importer",
	"spreporter":      "System Profiler reporter",
	"wdgt":            "widget",
	"docset":          "documentation set",
	"safariextension": "Safari extension",
	"saver":           "screen saver",
	"component":       "audio component",
	"driver":          "driver",
	"dext":            "driver extension",
	"applescript":     "script bundle",
	"scptd":           "script bundle",
	"workflow":        "workflow",
}

// Bundles returns every bundle the path sits inside, outermost first.
func Bundles(path string) []Bundle {
	if path == "" || path[0] != '/' {
		return nil
	}

	var out []Bundle
	parts := strings.Split(path, "/")
	at := ""

	for _, part := range parts {
		if part == "" {
			continue
		}
		at += "/" + part

		dot := strings.LastIndex(part, ".")
		if dot <= 0 {
			continue
		}

		ext, ok := bundleExt(part[dot+1:])
		if !ok {
			continue
		}

		out = append(out, Bundle{Name: part[:dot], Ext: ext, Path: at})
	}

	return out
}

func bundleExt(ext string) (string, bool) {
	if _, ok := bundleExts[ext]; ok {
		return ext, true
	}

	for known := range bundleExts {
		if strings.EqualFold(known, ext) {
			return known, true
		}
	}

	return "", false
}

// BundleWords is the table received through /api/labels.
func BundleWords() map[string]string {
	out := make(map[string]string, len(bundleExts))
	for ext, word := range bundleExts {
		out[ext] = word
	}

	return out
}

func BundleWord(ext string) string {
	if known, ok := bundleExt(ext); ok {
		return bundleExts[known]
	}

	return "bundle"
}

func PartOf(path string) string {
	bs := Bundles(path)
	if len(bs) == 0 {
		return ""
	}

	outer := bs[0]

	return outer.Name + " " + BundleWord(outer.Ext)
}
