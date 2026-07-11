package httpapi

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/deni336/DeniLicense/internal/config"
	"github.com/deni336/DeniLicense/internal/license"
)

func TestServerPublishesCurrentAndRetainedActivationKeys(t *testing.T) {
	current, err := license.GenerateSigningKey(license.PurposeActivationReceiptSigner)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := license.GenerateSigningKey(license.PurposeActivationReceiptSigner)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(config.Config{
		ActivationIssuer: "https://licenses.example.test",
		DevicePepper:     bytes.Repeat([]byte{1}, 32),
	}, nil, current, previous.VerificationKey(), current.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Close(ctx); err != nil {
			t.Errorf("close server: %v", err)
		}
	}()
	if len(server.activationKeys.Keys) != 2 {
		t.Fatalf("published key count = %d, want 2", len(server.activationKeys.Keys))
	}
	if _, err := server.activationKeys.Lookup(current.KeyID()); err != nil {
		t.Fatalf("current key lookup: %v", err)
	}
	if _, err := server.activationKeys.Lookup(previous.KeyID()); err != nil {
		t.Fatalf("retained key lookup: %v", err)
	}

	offline, err := license.GenerateSigningKey(license.PurposeOfflineLicenseIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Config{ActivationIssuer: "issuer"}, nil, current, offline.VerificationKey()); err == nil {
		t.Fatal("offline issuer key was accepted in the activation key ring")
	}
}
