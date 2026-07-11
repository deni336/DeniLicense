package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/deni336/DeniLicense/internal/config"
)

type emailSender struct {
	webhookURL string
	bearer     string
	publicURL  string
	client     *http.Client
	jobs       chan emailJob
	ctx        context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	mu         sync.RWMutex
	closed     bool
}

type emailJob struct {
	kind      string
	recipient string
	token     string
	requestID string
}

func newEmailSender(cfg config.Config) *emailSender {
	workerContext, cancelWorkers := context.WithCancel(context.Background())
	sender := &emailSender{
		webhookURL: cfg.EmailWebhookURL,
		bearer:     cfg.EmailWebhookBearer,
		publicURL:  cfg.PublicAppURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("email webhook redirects are not allowed")
			},
		},
		jobs:   make(chan emailJob, 256),
		ctx:    workerContext,
		cancel: cancelWorkers,
	}
	if sender.configured() {
		for range 2 {
			sender.workers.Add(1)
			go sender.run()
		}
	}
	return sender
}

func (s *emailSender) configured() bool { return s != nil && s.webhookURL != "" }

func (s *emailSender) sendVerification(ctx context.Context, recipient, token string) error {
	return s.sendLink(ctx, recipient, token, "denilicense-email-verification", "/verify-email?token=")
}

func (s *emailSender) sendPasswordReset(ctx context.Context, recipient, token string) error {
	return s.sendLink(ctx, recipient, token, "denilicense-password-reset", "/reset-password?token=")
}

// enqueue keeps auth responses independent of webhook latency. The queue is
// deliberately bounded so an unhealthy delivery adapter cannot create an
// unbounded number of goroutines or retain secrets indefinitely in memory.
func (s *emailSender) enqueue(kind, recipient, token, requestID string) bool {
	if !s.configured() || (kind != "verification" && kind != "password_reset") {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false
	}
	select {
	case s.jobs <- emailJob{kind: kind, recipient: recipient, token: token, requestID: requestID}:
		return true
	default:
		slog.Warn("email delivery queue full", "request_id", requestID, "kind", kind)
		return false
	}
}

func (s *emailSender) run() {
	defer s.workers.Done()
	for job := range s.jobs {
		if err := s.deliver(job); err != nil && s.ctx.Err() == nil {
			// Recipient addresses and bearer tokens are intentionally excluded.
			slog.Warn("email delivery failed", "request_id", job.requestID, "kind", job.kind, "error", err)
		}
	}
}

func (s *emailSender) deliver(job emailJob) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		switch job.kind {
		case "verification":
			lastErr = s.sendVerification(ctx, job.recipient, job.token)
		case "password_reset":
			lastErr = s.sendPasswordReset(ctx, job.recipient, job.token)
		default:
			lastErr = errors.New("unknown email job")
		}
		cancel()
		if lastErr == nil {
			return nil
		}
		if attempt < 2 {
			delay := time.Duration(1<<attempt) * 500 * time.Millisecond
			select {
			case <-time.After(delay):
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}
	}
	return lastErr
}

func (s *emailSender) close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.jobs)
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.cancel()
		return nil
	case <-ctx.Done():
		s.cancel()
		<-done
		return ctx.Err()
	}
}

func (s *emailSender) sendLink(ctx context.Context, recipient, token, template, path string) error {
	if !s.configured() {
		return errors.New("email webhook is not configured")
	}
	actionURL := s.publicURL + path + url.QueryEscape(token)
	payload, err := json.Marshal(map[string]string{
		"template":  template,
		"recipient": recipient,
		"actionUrl": actionURL,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.bearer)
	request.Header.Set("User-Agent", "DeniLicense/1")
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("email webhook: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("email webhook returned status %d", response.StatusCode)
	}
	return nil
}
