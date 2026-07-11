package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deni336/DeniLicense/internal/config"
)

func TestEmailWebhookReceivesAuthenticatedActionLink(t *testing.T) {
	var gotAuthorization string
	var gotPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender := newEmailSender(config.Config{
		EmailWebhookURL: server.URL, EmailWebhookBearer: "webhook-secret",
		PublicAppURL: "https://licenses.example.com",
	})
	defer closeTestEmailSender(t, sender)
	if err := sender.sendVerification(t.Context(), "customer@example.com", "dlev_secret"); err != nil {
		t.Fatal(err)
	}
	if gotAuthorization != "Bearer webhook-secret" {
		t.Fatalf("authorization = %q", gotAuthorization)
	}
	if gotPayload["recipient"] != "customer@example.com" || gotPayload["actionUrl"] != "https://licenses.example.com/verify-email?token=dlev_secret" {
		t.Fatalf("unexpected webhook payload: %#v", gotPayload)
	}
}

func TestEmailQueueDeliversWithoutBlockingCaller(t *testing.T) {
	delivered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender := newEmailSender(config.Config{
		EmailWebhookURL: server.URL, EmailWebhookBearer: "webhook-secret",
		PublicAppURL: "https://licenses.example.com",
	})
	defer closeTestEmailSender(t, sender)
	if !sender.enqueue("password_reset", "customer@example.com", "dlpr_secret", "request-1") {
		t.Fatal("email job was not accepted")
	}
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("queued email was not delivered")
	}
}

func TestEmailWebhookDoesNotFollowRedirects(t *testing.T) {
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	sender := newEmailSender(config.Config{
		EmailWebhookURL: redirector.URL, EmailWebhookBearer: "webhook-secret",
		PublicAppURL: "https://licenses.example.com",
	})
	defer closeTestEmailSender(t, sender)
	if err := sender.sendVerification(t.Context(), "customer@example.com", "dlev_secret"); err == nil {
		t.Fatal("webhook redirect was followed")
	}
	if redirectTargetCalled {
		t.Fatal("redirect target received the email payload")
	}
}

func TestEmailQueueRetriesTransientFailure(t *testing.T) {
	attempts := 0
	delivered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		delivered <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	sender := newEmailSender(config.Config{
		EmailWebhookURL: server.URL, EmailWebhookBearer: "webhook-secret",
		PublicAppURL: "https://licenses.example.com",
	})
	defer closeTestEmailSender(t, sender)
	if !sender.enqueue("verification", "customer@example.com", "dlev_secret", "request-retry") {
		t.Fatal("email job was not accepted")
	}
	select {
	case <-delivered:
	case <-time.After(4 * time.Second):
		t.Fatal("transient webhook failure was not retried")
	}
	if attempts != 3 {
		t.Fatalf("delivery attempts = %d, want 3", attempts)
	}
}

func closeTestEmailSender(t *testing.T, sender *emailSender) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sender.close(ctx); err != nil {
		t.Errorf("close email sender: %v", err)
	}
}
