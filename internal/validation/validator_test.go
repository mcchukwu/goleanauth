package validation

import "testing"

type uriFixture struct {
	Value string
	Valid bool
}

func TestAbsoluteURIRule(t *testing.T) {
	Init()

	fixtures := []uriFixture{
		{"https://app.example.com/cb", true},
		{"http://localhost:8080/cb", true},
		{"https://app.example.com/cb?x=1", true},
		{"", true}, // optional fields pass when empty
		{"not-a-url", false},
		{"ftp://app.example.com/cb", false},
		{"/relative/path", false},
		{"https://", false},
	}

	for _, f := range fixtures {
		fields := ValidateStruct(struct {
			URI string `validate:"absolute_uri"`
		}{URI: f.Value})
		gotValid := len(fields) == 0
		if gotValid != f.Valid {
			t.Errorf("absolute_uri(%q) valid=%v, want %v", f.Value, gotValid, f.Valid)
		}
	}
}
