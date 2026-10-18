package event

import "testing"

func TestParseUID(t *testing.T) {
	for in, want := range map[string]uint32{
		"0":          0,
		"501":        501,
		"uid 501":    501,
		"  uid 501 ": 501,
		"4294967294": 4294967294, // nobody, as the log writes it
		"4294967295": NoAUID,
	} {
		got, ok := ParseUID(in)
		if !ok || got != want {
			t.Errorf("ParseUID(%q) = %d, %v; want %d, true", in, got, ok, want)
		}
	}

	for _, in := range []string{"", "-1", "4294967296",
		"18446744073709551616", "501x", "0x1f5", "nobody", " ", "uid "} {
		if got, ok := ParseUID(in); ok {
			t.Errorf("ParseUID(%q) = %d, true; want rejected", in, got)
		}
	}
}
