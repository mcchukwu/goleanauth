package normalize

import "testing"

func TestEmail(t *testing.T) {
	cases := map[string]string{
		"  MiRACLE@Example.COM ": "miracle@example.com",
		"user@domain.io":         "user@domain.io",
		"":                       "",
	}
	for input, want := range cases {
		if got := Email(input); got != want {
			t.Errorf("Email(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPhone(t *testing.T) {
	cases := []struct {
		name    string
		phone   string
		region  string
		want    string
		wantErr bool
	}{
		{name: "already E.164", phone: "+2348012345678", region: "", want: "+2348012345678"},
		{name: "local NG with region", phone: "08012345678", region: "NG", want: "+2348012345678"},
		{name: "stripped separators", phone: "+1 234-567-8900", region: "", want: "+12345678900"},
		{name: "garbage", phone: "abc", region: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Phone(tc.phone, tc.region)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Phone(%q) expected error, got %q", tc.phone, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Phone(%q) unexpected error: %v", tc.phone, err)
			}
			if got != tc.want {
				t.Errorf("Phone(%q) = %q, want %q", tc.phone, got, tc.want)
			}
		})
	}
}

func TestIdentifier(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		region string
		want   string
	}{
		{name: "email lowercased", in: "  MiRACLE@Example.COM ", region: "", want: "miracle@example.com"},
		{name: "ng phone", in: "08012345678", region: "NG", want: "+2348012345678"},
		{name: "invalid kept as-is", in: "garbage!!", region: "", want: "garbage!!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Identifier(tc.in, tc.region); got != tc.want {
				t.Errorf("Identifier(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
