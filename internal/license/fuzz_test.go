package license

import "testing"

func FuzzVerifyToken(f *testing.F) {
	key := testSigningKey(f, PurposeOfflineLicenseIssuer)
	valid, err := SignToken(testClaims(f, key), key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("dlic1...")
	f.Add("dlic1.e30.AA")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = VerifyToken(token, key.VerificationKey())
		_, _ = InspectUnverified(token)
	})
}

func FuzzStrictJSONParsers(f *testing.F) {
	key := testSigningKey(f, PurposeOfflineLicenseIssuer)
	claims, err := testClaims(f, key).CanonicalJSON()
	if err != nil {
		f.Fatal(err)
	}
	public, err := MarshalPublicKey(key.VerificationKey())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(claims)
	f.Add(public)
	f.Add([]byte(`{"a":{"a":1,"a":2}}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCanonicalClaims(data)
		_, _ = ParsePublicKey(data)
	})
}
