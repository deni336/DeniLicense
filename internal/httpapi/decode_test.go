package httpapi

import "testing"

func TestRejectDuplicateKeysAtAnyDepth(t *testing.T) {
	tests := []string{
		`{"email":"first@example.com","email":"second@example.com"}`,
		`{"outer":{"value":1,"value":2}}`,
		`{"items":[{"key":true,"key":false}]}`,
	}
	for _, test := range tests {
		if err := rejectDuplicateKeys([]byte(test)); err == nil {
			t.Fatalf("accepted duplicate keys in %s", test)
		}
	}
}

func TestAcceptUniqueJSON(t *testing.T) {
	if err := rejectDuplicateKeys([]byte(`{"outer":{"value":1},"items":[true,"x"]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectCaseInsensitiveDuplicateKeys(t *testing.T) {
	if err := rejectDuplicateKeys([]byte(`{"state":"active","State":"revoked"}`)); err == nil {
		t.Fatal("case-insensitive duplicate was accepted")
	}
}

func TestRequireExactTopLevelFields(t *testing.T) {
	destination := struct {
		State string `json:"state"`
	}{}
	if err := requireExactTopLevelFields([]byte(`{"State":"active"}`), &destination); err == nil {
		t.Fatal("incorrectly cased field was accepted")
	}
}

func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"value":1}`))
	f.Add([]byte(`{"value":1,"value":2}`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_ = rejectDuplicateKeys(encoded)
	})
}
