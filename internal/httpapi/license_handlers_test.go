package httpapi

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestIdempotencyKeyValidation(t *testing.T) {
	for _, value := range []string{"request-123", "A2345678", "release:customer_4.2"} {
		if !validIdempotencyKey(value) {
			t.Errorf("valid key rejected: %q", value)
		}
	}
	for _, value := range []string{"", "short", " leading-space", "contains/slash", "contains space"} {
		if validIdempotencyKey(value) {
			t.Errorf("invalid key accepted: %q", value)
		}
	}
}

func TestOnlineIssuanceDerivationIsBoundToPurposeActorKeyAndRequest(t *testing.T) {
	pepper := bytes.Repeat([]byte{7}, 32)
	actor := uuid.New()
	requestHash := bytes.Repeat([]byte{9}, 32)
	baseline := deriveOnlineIssuance(pepper, "claim-code", actor, "request-123", requestHash)
	if baseline != deriveOnlineIssuance(pepper, "claim-code", actor, "request-123", requestHash) {
		t.Fatal("derivation is not deterministic")
	}
	if baseline == deriveOnlineIssuance(pepper, "serial", actor, "request-123", requestHash) {
		t.Fatal("purpose was not domain separated")
	}
	if baseline == deriveOnlineIssuance(pepper, "claim-code", uuid.New(), "request-123", requestHash) {
		t.Fatal("actor was not bound")
	}
	if baseline == deriveOnlineIssuance(pepper, "claim-code", actor, "request-456", requestHash) {
		t.Fatal("idempotency key was not bound")
	}
	requestHash[0] ^= 1
	if baseline == deriveOnlineIssuance(pepper, "claim-code", actor, "request-123", requestHash) {
		t.Fatal("request hash was not bound")
	}
}
