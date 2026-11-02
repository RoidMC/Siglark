package nxs

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalOriginFixtures(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nxs/origins.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Vectors []struct {
			Origin   string `json:"origin"`
			Accepted bool   `json:"accepted"`
			Category string `json:"category"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("no origin vectors")
	}
	failures := 0
	for _, v := range fx.Vectors {
		err := ValidateOrigin(v.Origin)
		if got, want := err == nil, v.Accepted; got != want {
			failures++
			if failures <= 20 {
				t.Errorf("origin %q [%s]: accepted=%v, want %v (err=%v)", v.Origin, v.Category, got, want, err)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d origin vectors failed", failures, len(fx.Vectors))
	}
}

func TestValidateOriginBasics(t *testing.T) {
	valid := []string{
		"https://provider.example",
		"https://provider.example:8080",
		"https://127.0.0.1",
		"https://[::1]:8443",
		"https://[2001:db8::1]",
		"http://localhost:8080",
	}
	for _, o := range valid {
		if err := ValidateOrigin(o); err != nil {
			t.Errorf("%q should be valid: %v", o, err)
		}
	}
	invalid := []string{
		"https://Provider.example",
		"https://provider.example/",
		"https://provider.example?x=1",
		"https://provider.example:443",
		"https://user@provider.example",
		"https://provider.example.",
		"http://provider.example",
		"https://01.2.3.4",
		"https://[2001:0db8::1]",
	}
	for _, o := range invalid {
		if err := ValidateOrigin(o); err == nil {
			t.Errorf("%q should be invalid", o)
		}
	}
}
