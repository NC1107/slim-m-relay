// SPDX-License-Identifier: Apache-2.0

// Package apns forwards content-free pushes to Apple Push Notification service (APNs) for
// iOS devices, using token-based (.p8 key) authentication via github.com/sideshow/apns2,
// the standard Go APNs client.
//
// Every notification it sends is a silent background push: aps carries only
// content-available and mutable-content, never an alert, sound, or badge, so APNs itself -
// and its logs - never see plaintext. The home server's already-encrypted payload and the
// coarse kind travel as custom top-level fields; the device wakes in the background and
// decrypts locally to decide how, or whether, to surface a notification. A real ringing
// VoIP call would need PushKit and its own entitlement, which is out of scope for this
// content-free relay.
package apns

import (
	"context"
	"fmt"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// client is the slice of *apns2.Client this package depends on, named as an interface so
// tests can substitute a fake gateway.
type client interface {
	PushWithContext(ctx apns2.Context, n *apns2.Notification) (*apns2.Response, error)
}

// Sender holds the APNs token client and posts notifications to the gateway.
type Sender struct {
	client   client
	bundleID string
}

// Config is the token-based (.p8) credential set required to reach APNs.
type Config struct {
	// KeyPath is the path to the .p8 private key downloaded from the Apple Developer portal.
	KeyPath string
	// KeyID is the 10-character key identifier for that .p8 key.
	KeyID string
	// TeamID is the 10-character Apple Developer Team ID.
	TeamID string
	// BundleID is the app's bundle identifier; used as the APNs topic.
	BundleID string
	// Production selects APNs' production gateway. false uses the sandbox gateway, which
	// is what devices running a debug/development build register against.
	Production bool
}

// New builds a Sender from a .p8 token key. Callers only reach this once all four
// credential fields are non-empty (see cmd/relay); an incomplete or absent configuration is
// the caller's decision to route to push.Unconfigured instead, not an error this
// constructor raises. Once here, a credential that is present but unusable (a bad .p8 file,
// for instance) is a real misconfiguration and is returned as an error.
func New(cfg Config) (*Sender, error) {
	authKey, err := token.AuthKeyFromFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("apns: read .p8 key: %w", err)
	}
	tok := &token.Token{AuthKey: authKey, KeyID: cfg.KeyID, TeamID: cfg.TeamID}
	c := apns2.NewTokenClient(tok)
	if cfg.Production {
		c = c.Production()
	} else {
		c = c.Development()
	}
	return &Sender{client: c, bundleID: cfg.BundleID}, nil
}

// Send posts every message to APNs and returns one push.Result per input in the same
// order. It never logs the token or the payload; the caller decides what to record from the
// returned statuses.
func (s *Sender) Send(ctx context.Context, msgs []push.Message) []push.Result {
	results := make([]push.Result, len(msgs))
	for i, m := range msgs {
		results[i] = push.Result{Token: m.Token, Status: s.sendOne(ctx, m)}
	}
	return results
}

func (s *Sender) sendOne(ctx context.Context, m push.Message) push.Status {
	p := payload.NewPayload().ContentAvailable().MutableContent()
	p.Custom("kind", string(m.Kind))
	p.Custom("payload", m.Payload)

	n := &apns2.Notification{
		DeviceToken: m.Token,
		Topic:       s.bundleID,
		PushType:    apns2.PushTypeBackground,
		// A content-available-only push must use low priority; APNs rejects high priority
		// (10) unless the payload also triggers a user-visible alert, sound, or badge.
		Priority: apns2.PriorityLow,
		Payload:  p,
	}
	resp, err := s.client.PushWithContext(ctx, n)
	if err != nil {
		return push.StatusError
	}
	if resp.Sent() {
		return push.StatusDelivered
	}
	switch resp.Reason {
	case apns2.ReasonUnregistered, apns2.ReasonBadDeviceToken, apns2.ReasonExpiredToken:
		return push.StatusUnregistered
	default:
		return push.StatusError
	}
}
