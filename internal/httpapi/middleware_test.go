package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientSourceResolverUsesOnlyTrustedProxyChains(t *testing.T) {
	resolver, err := newClientSourceResolver(
		[]string{"10.0.0.0/8", "fd00::/8"},
		[]byte(strings.Repeat("p", 32)),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{
			name:       "untrusted peer cannot spoof header",
			remoteAddr: "192.0.2.10:4321",
			forwarded:  "198.51.100.99",
			want:       "192.0.2.10",
		},
		{
			name:       "trusted peer supplies client",
			remoteAddr: "10.0.0.10:4321",
			forwarded:  "198.51.100.20",
			want:       "198.51.100.20",
		},
		{
			name:       "trusted chain ignores spoofable left entries",
			remoteAddr: "10.0.0.10:4321",
			forwarded:  "192.0.2.200, 198.51.100.20, 10.1.2.3",
			want:       "198.51.100.20",
		},
		{
			name:       "malformed trusted chain fails closed",
			remoteAddr: "10.0.0.10:4321",
			forwarded:  "not-an-address",
			want:       "10.0.0.10",
		},
		{
			name:       "trusted IPv6 peer supplies client",
			remoteAddr: "[fd00::10]:4321",
			forwarded:  "2001:db8::20",
			want:       "2001:db8::20",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.test/resource", nil)
			request.RemoteAddr = test.remoteAddr
			if test.forwarded != "" {
				request.Header.Set("X-Forwarded-For", test.forwarded)
			}
			if got := resolver.address(request); got != test.want {
				t.Fatalf("address = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClientSourceResolverRejectsInvalidCIDR(t *testing.T) {
	if _, err := newClientSourceResolver([]string{"10.0.0.0/99"}, []byte(strings.Repeat("p", 32))); err == nil {
		t.Fatal("invalid trusted proxy CIDR was accepted")
	}
}

func TestRateLimiterIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	resolver, err := newClientSourceResolver([]string{"10.0.0.0/8"}, []byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	limiter := newRateLimiter(1, time.Hour, resolver)
	handler := limiter.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for index, forwarded := range []string{"198.51.100.1", "198.51.100.2"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/resource", nil)
		request.RemoteAddr = "192.0.2.10:4321"
		request.Header.Set("X-Forwarded-For", forwarded)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		want := http.StatusNoContent
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("request %d status = %d, want %d", index+1, response.Code, want)
		}
	}
}

func TestLoggingMiddlewareRecordsResponseAndHashedSource(t *testing.T) {
	pepper := []byte(strings.Repeat("p", 32))
	resolver, err := newClientSourceResolver([]string{"10.0.0.0/8"}, pepper)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://example.test/resource?token=secret", nil)
	request.RemoteAddr = "10.0.0.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	wantHash := resolver.hash(request)

	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	handler := requestMiddleware(false)(loggingMiddleware(resolver)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("accepted"))
	})))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("decode log event: %v\n%s", err, output.String())
	}
	if got := int(event["status"].(float64)); got != http.StatusAccepted {
		t.Fatalf("logged status = %d, want %d", got, http.StatusAccepted)
	}
	if got := int(event["bytes"].(float64)); got != len("accepted") {
		t.Fatalf("logged bytes = %d, want %d", got, len("accepted"))
	}
	if got := event["source_hash"]; got != wantHash {
		t.Fatalf("source_hash = %v, want %q", got, wantHash)
	}
	if got := event["path"]; got != "/resource" {
		t.Fatalf("path = %v, want /resource", got)
	}
	for _, sensitive := range []string{"198.51.100.20", "10.0.0.10", "token=secret"} {
		if strings.Contains(output.String(), sensitive) {
			t.Fatalf("request log exposed %q: %s", sensitive, output.String())
		}
	}
}
