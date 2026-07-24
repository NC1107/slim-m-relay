// SPDX-License-Identifier: Apache-2.0

// Package push defines the vocabulary the relay's two provider clients (internal/fcm and
// internal/apns) share, so /v1/send can dispatch a message to whichever platform it
// declares through one interface, without either provider package importing the other or
// the API package importing both concrete types.
package push

import (
	"context"
	"log"
)

// Platform selects which provider a message is forwarded through.
type Platform string

const (
	// PlatformIOS routes a message to Apple Push Notification service.
	PlatformIOS Platform = "ios"
	// PlatformAndroid routes a message to Firebase Cloud Messaging.
	PlatformAndroid Platform = "android"
)

// Kind is the coarse, content-free notification category the home server declares. The
// relay never looks inside Payload, so Kind is the only signal it forwards about what
// happened - just enough for a device to decide how urgently to wake and what to fetch.
type Kind string

const (
	KindMessage Kind = "message"
	KindMention Kind = "mention"
	KindCall    Kind = "call"
	KindWake    Kind = "wake"
)

// Message is one push bound for one device token. Payload is an opaque blob the home
// server already encrypted before it ever reached the relay; the relay forwards it
// untouched, never decrypts it, and never logs it.
type Message struct {
	Token   string
	Kind    Kind
	Payload string
}

// Status is the delivery outcome for one token.
type Status string

const (
	// StatusDelivered means the provider accepted the message.
	StatusDelivered Status = "delivered"
	// StatusUnregistered means the provider reports the token as no longer valid; the
	// caller should delete it from its own store.
	StatusUnregistered Status = "unregistered"
	// StatusForbidden means the token is bound to a different key (see internal/keys) and
	// this send was refused, so one self-hosted server cannot harass another's devices.
	StatusForbidden Status = "forbidden"
	// StatusError means the send failed for some other reason and may be worth a retry.
	StatusError Status = "error"
)

// Result pairs an input token with its delivery outcome.
type Result struct {
	Token  string `json:"token"`
	Status Status `json:"status"`
}

// Sender is implemented by both internal/fcm and internal/apns, so the API layer can
// dispatch a send by platform through one interface.
type Sender interface {
	Send(ctx context.Context, msgs []Message) []Result
}

// Unconfigured returns a Sender that rejects every message with StatusError, logging why
// exactly once per call. main wires this in for whichever platform is missing its
// credentials, so the relay can start and serve every other endpoint - registration,
// sending on the other platform, admin, health - without secrets it was never given.
func Unconfigured(platform string) Sender { return unconfigured{platform: platform} }

type unconfigured struct{ platform string }

func (u unconfigured) Send(_ context.Context, msgs []Message) []Result {
	if len(msgs) > 0 {
		log.Printf("relay: %s not configured; rejecting %d message(s)", u.platform, len(msgs))
	}
	out := make([]Result, len(msgs))
	for i, m := range msgs {
		out[i] = Result{Token: m.Token, Status: StatusError}
	}
	return out
}
