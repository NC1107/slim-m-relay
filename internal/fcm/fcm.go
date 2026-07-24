// SPDX-License-Identifier: Apache-2.0

// Package fcm forwards content-free pushes to Firebase Cloud Messaging (FCM HTTP v1) for
// Android devices. It talks to the REST API directly with an OAuth2 token minted from a
// service account, avoiding the heavyweight Firebase Admin SDK.
//
// Every message it sends is data-only: the home server's already-encrypted payload and the
// coarse kind travel as opaque data fields, never as a plaintext notification title or
// body, so FCM itself - and its logs - never see content. The device wakes in the
// background and decrypts locally to decide how, or whether, to surface a notification.
package fcm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/nc1107/slim-m-relay/internal/push"
)

const (
	scope    = "https://www.googleapis.com/auth/firebase.messaging"
	endpoint = "https://fcm.googleapis.com"
)

// Sender holds the FCM credentials and posts messages to the REST API.
type Sender struct {
	tokens    oauth2.TokenSource
	projectID string
	http      *http.Client
	endpoint  string
}

// New builds a Sender from a Firebase service-account JSON.
func New(ctx context.Context, credentialsJSON []byte) (*Sender, error) {
	creds, err := google.CredentialsFromJSON(ctx, credentialsJSON, scope)
	if err != nil {
		return nil, fmt.Errorf("parse FCM credentials: %w", err)
	}
	if creds.ProjectID == "" {
		return nil, fmt.Errorf("FCM credentials missing project_id")
	}
	return &Sender{
		tokens:    creds.TokenSource,
		projectID: creds.ProjectID,
		http:      &http.Client{Timeout: 15 * time.Second},
		endpoint:  endpoint,
	}, nil
}

// ProjectID is the Firebase project these notifications are sent through.
func (s *Sender) ProjectID() string { return s.projectID }

// Send delivers every message and returns one push.Result per input in the same order (FCM
// v1 has no multicast, so it is one request per token). It never logs the token or the
// payload; the caller decides what to record from the returned statuses.
func (s *Sender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	results := make([]push.Result, len(msgs))
	tok, err := s.tokens.Token()
	if err != nil {
		for i, m := range msgs {
			results[i] = push.Result{Token: m.Token, Status: push.StatusError}
		}
		return results
	}
	url := fmt.Sprintf("%s/v1/projects/%s/messages:send", s.endpoint, s.projectID)
	for i, m := range msgs {
		results[i] = push.Result{Token: m.Token, Status: s.sendOne(ctx, url, tok.AccessToken, m)}
	}
	return results
}

func (s *Sender) sendOne(ctx context.Context, url, access string, m push.Message) push.Status {
	body, _ := json.Marshal(map[string]any{
		"message": map[string]any{
			"token": m.Token,
			// Data-only: kind and the opaque ciphertext are the only fields, so FCM never
			// renders (and never sees) a plaintext notification on the relay's behalf.
			"data": map[string]string{
				"kind":    string(m.Kind),
				"payload": m.Payload,
			},
			// High priority wakes the app promptly even while backgrounded; the payload is
			// opaque, so timely delivery is the only lever the relay has.
			"android": map[string]any{"priority": "high"},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return push.StatusError
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return push.StatusError
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		return push.StatusDelivered
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if errorCode(raw) == "UNREGISTERED" {
		return push.StatusUnregistered
	}
	return push.StatusError
}

// errorCode pulls FCM v1's machine-readable code out of an error response, preferring the
// specific code in details (e.g. UNREGISTERED) over the generic status. Returns "" when the
// body isn't the shape we expect.
func errorCode(body []byte) string {
	var resp struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	for _, d := range resp.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return resp.Error.Status
}
