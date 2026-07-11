package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deni336/DeniLicense/internal/auth"
	"github.com/deni336/DeniLicense/internal/domain"
	"github.com/deni336/DeniLicense/internal/store/postgres"
)

type contextKey string

const (
	requestIDKey contextKey = "request-id"
	principalKey contextKey = "principal"
)

var (
	errBadRequest       = errors.New("bad request")
	errUnauthenticated  = errors.New("unauthenticated")
	errForbidden        = errors.New("forbidden")
	errEmailUnverified  = errors.New("email unverified")
	errRateLimited      = errors.New("rate limited")
	errRouteNotFound    = errors.New("route not found")
	errMethodNotAllowed = errors.New("method not allowed")
)

func requestMiddleware(production bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := newRequestID()
			w.Header().Set("X-Request-ID", id)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			if production {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			ctx := context.WithValue(r.Context(), requestIDKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.ErrorContext(r.Context(), "panic recovered", "request_id", requestIDFrom(r.Context()), "panic", recovered, "stack", string(debug.Stack()))
				writeProblem(w, r, errors.New("panic"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseMetricsWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *responseMetricsWriter) WriteHeader(statusCode int) {
	if w.statusCode != 0 {
		return
	}
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseMetricsWriter) Write(value []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(value)
	w.bytesWritten += written
	return written, err
}

// Unwrap lets http.ResponseController reach optional interfaces implemented by
// the underlying writer without exposing a raw client address to the logger.
func (w *responseMetricsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseMetricsWriter) status() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func loggingMiddleware(source clientSourceResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			metrics := &responseMetricsWriter{ResponseWriter: w}
			defer func() {
				slog.InfoContext(r.Context(), "request",
					"request_id", requestIDFrom(r.Context()),
					"method", r.Method,
					"path", r.URL.Path,
					"status", metrics.status(),
					"bytes", metrics.bytesWritten,
					"duration_ms", time.Since(start).Milliseconds(),
					"source_hash", source.hash(r),
				)
			}()
			next.ServeHTTP(metrics, r)
		})
	}
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "request-id-unavailable"
	}
	return hex.EncodeToString(raw[:])
}

func authenticate(db *postgres.Store, pepper []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if len(header) < 8 || !strings.EqualFold(header[:7], "Bearer ") {
			writeProblem(w, r, errUnauthenticated)
			return
		}
		token := strings.TrimSpace(header[7:])
		hash, err := auth.HashToken(pepper, auth.AccessToken, token)
		if err != nil {
			writeProblem(w, r, errUnauthenticated)
			return
		}
		principal, err := db.PrincipalByAccessHash(r.Context(), hash, time.Now().UTC())
		if err != nil {
			writeProblem(w, r, errUnauthenticated)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireVerified(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principalFrom(r.Context()).User.EmailVerifiedAt == nil {
			writeProblem(w, r, errEmailUnverified)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireRoles(roles ...domain.Role) func(http.Handler) http.Handler {
	allowed := make(map[domain.Role]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := allowed[principalFrom(r.Context()).User.Role]; !ok {
				writeProblem(w, r, errForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func principalFrom(ctx context.Context) domain.Principal {
	p, _ := ctx.Value(principalKey).(domain.Principal)
	return p
}

type bucket struct {
	tokens float64
	last   time.Time
}

type clientSourceResolver struct {
	trustedProxies []*net.IPNet
	hashKey        []byte
}

func newClientSourceResolver(trustedProxyCIDRs []string, hashKey []byte) (clientSourceResolver, error) {
	resolver := clientSourceResolver{
		trustedProxies: make([]*net.IPNet, 0, len(trustedProxyCIDRs)),
		hashKey:        append([]byte(nil), hashKey...),
	}
	for _, encoded := range trustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(encoded))
		if err != nil {
			return clientSourceResolver{}, fmt.Errorf("parse trusted proxy CIDR %q: %w", encoded, err)
		}
		resolver.trustedProxies = append(resolver.trustedProxies, network)
	}
	return resolver, nil
}

func (s clientSourceResolver) address(r *http.Request) string {
	peer := parseRemoteIP(r.RemoteAddr)
	if peer == nil {
		return "unknown"
	}
	if !s.trusted(peer) {
		return peer.String()
	}

	forwardedValues := r.Header.Values("X-Forwarded-For")
	if len(forwardedValues) == 0 {
		return peer.String()
	}
	forwarded := strings.Split(strings.Join(forwardedValues, ","), ",")
	candidate := peer
	for index := len(forwarded) - 1; index >= 0 && s.trusted(candidate); index-- {
		next := net.ParseIP(strings.TrimSpace(forwarded[index]))
		if next == nil {
			// A malformed chain is not trustworthy; fall back to the transport
			// peer instead of accepting a partially parsed, attacker-controlled hop.
			return peer.String()
		}
		candidate = next
	}
	return candidate.String()
}

func (s clientSourceResolver) trusted(address net.IP) bool {
	for _, network := range s.trustedProxies {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

func (s clientSourceResolver) hash(r *http.Request) string {
	mac := hmac.New(sha256.New, s.hashKey)
	_, _ = mac.Write([]byte("DeniLicense/request-source/v1\x00"))
	_, _ = mac.Write([]byte(s.address(r)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseRemoteIP(remoteAddress string) net.IP {
	host := strings.TrimSpace(remoteAddress)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	return net.ParseIP(host)
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]bucket
	capacity float64
	refill   float64
	lastGC   time.Time
	source   clientSourceResolver
}

func newRateLimiter(capacity int, window time.Duration, source clientSourceResolver) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]bucket),
		capacity: float64(capacity),
		refill:   float64(capacity) / window.Seconds(),
		lastGC:   time.Now(),
		source:   source,
	}
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := l.source.address(r)
		allowed, retryAfter := l.allow(key, time.Now())
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
			writeProblem(w, r, errRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *rateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b.last.IsZero() {
		b = bucket{tokens: l.capacity, last: now}
	}
	b.tokens += now.Sub(b.last).Seconds() * l.refill
	if b.tokens > l.capacity {
		b.tokens = l.capacity
	}
	b.last = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.buckets[key] = b
	if now.Sub(l.lastGC) > 10*time.Minute {
		for candidate, entry := range l.buckets {
			if now.Sub(entry.last) > time.Hour {
				delete(l.buckets, candidate)
			}
		}
		l.lastGC = now
	}
	if allowed {
		return true, 0
	}
	retry := time.Duration((1 - b.tokens) / l.refill * float64(time.Second))
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry
}
