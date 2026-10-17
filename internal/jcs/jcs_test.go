package jcs

import (
	"encoding/json"
	"testing"
)

func TestMarshalCanonical(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"sorted keys", map[string]any{"b": 1, "a": "x", "ä": true}, `{"a":"x","b":1,"ä":true}`},
		{"rfc 8785 section 3.2.3 order", map[string]any{
			"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
			"\U0001F602": "Smiley", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis",
		}, `{"\r":"Carriage Return","1":"One","` + "\u0080" + `":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","` + "\ufb33" + `":"Hebrew Letter Dalet With Dagesh"}`},
		{"escapes", "a\"b\\c\n\t\u0001\u007f<>& ", `"a\"b\\c\n\t\u0001` + "\u007f<>& " + `"`},
		{"nested", map[string]any{"z": []any{nil, false, int64(42), map[string]any{"k": "v"}}}, `{"z":[null,false,42,{"k":"v"}]}`},
		{"string slice", []string{"b", "a"}, `["b","a"]`},
		{"max int", int64(MaxInt), "9007199254740991"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := Marshal(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
			if !json.Valid(got) {
				t.Fatalf("output is not valid JSON: %s", got)
			}
		})
	}
}

func TestMarshalRejects(t *testing.T) {
	t.Parallel()
	for name, v := range map[string]any{
		"too large":    int64(MaxInt + 1),
		"float":        1.5,
		"invalid utf8": "\xff",
		"struct":       struct{}{},
	} {
		if _, err := Marshal(v); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
