package claimcode

import (
	"strings"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	code, wantDigest, suffix, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, "DNL1-") {
		t.Fatalf("unexpected code prefix: %q", code)
	}
	gotDigest, err := Digest(strings.ToLower(code))
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatal("digest changed after display normalization")
	}
	gotSuffix, err := Suffix(code)
	if err != nil {
		t.Fatal(err)
	}
	if gotSuffix != suffix {
		t.Fatalf("suffix = %q, want %q", gotSuffix, suffix)
	}
}

func TestRejectsMutation(t *testing.T) {
	code, _, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	mutated := []byte(code)
	for i := len(mutated) - 1; i >= 0; i-- {
		if mutated[i] == '-' {
			continue
		}
		if mutated[i] == '0' {
			mutated[i] = '1'
		} else {
			mutated[i] = '0'
		}
		break
	}
	if _, err := Parse(string(mutated)); err == nil {
		t.Fatal("mutated code was accepted")
	}
}

func TestDigestIsDomainSeparated(t *testing.T) {
	raw := make([]byte, randomByteCount)
	got := DigestRaw(raw)
	if got == [32]byte{} {
		t.Fatal("unexpected zero digest")
	}
}

func TestFromEntropyIsDeterministic(t *testing.T) {
	raw := make([]byte, randomByteCount)
	first, firstDigest, firstSuffix, err := FromEntropy(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, secondSuffix, err := FromEntropy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || firstDigest != secondDigest || firstSuffix != secondSuffix {
		t.Fatal("same entropy produced different claim codes")
	}
	if _, _, _, err := FromEntropy(raw[:len(raw)-1]); err == nil {
		t.Fatal("short entropy was accepted")
	}
}

func FuzzParse(f *testing.F) {
	code, _, _, _ := Generate()
	f.Add(code)
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = Parse(value)
	})
}
