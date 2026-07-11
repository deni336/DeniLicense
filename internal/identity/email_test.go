package identity

import "testing"

func TestNormalizeEmail(t *testing.T) {
	display, normalized, err := NormalizeEmail("Owner@Example.COM")
	if err != nil || display != "Owner@Example.COM" || normalized != "owner@example.com" {
		t.Fatalf("NormalizeEmail = %q, %q, %v", display, normalized, err)
	}
	for _, value := range []string{"owner@localhost", "Display <owner@example.com>", "owner@example.com\n", "owner@例.example"} {
		if _, _, err := NormalizeEmail(value); err == nil {
			t.Fatalf("accepted invalid email %q", value)
		}
	}
}
