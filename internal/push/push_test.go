// SPDX-License-Identifier: Apache-2.0

package push

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

// Unconfigured must log its rejection at most once per request scope, no matter how many
// times Send is called within it. dispatch calls Send once per message rather than once
// per batch, so without this dedupe a large batch against an unconfigured provider writes
// one log line per token - attacker-driven disk amplification against a supported
// configuration (a relay started without one platform's credentials is explicitly
// non-fatal).
func TestUnconfiguredLogsOncePerRequestScope(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := Unconfigured("fcm")
	ctx := WithRequestScope(context.Background())
	for i := 0; i < 500; i++ {
		s.Send(ctx, []Message{{Token: "t", Kind: KindWake, Payload: "c"}})
	}

	got := strings.Count(buf.String(), "fcm not configured")
	if got != 1 {
		t.Errorf("logged %d times across 500 Send calls in one request scope, want exactly 1", got)
	}
}

// Two independent request scopes must each still get their own log line: the dedupe is
// per request, not a permanent one-shot for the process.
func TestUnconfiguredLogsOncePerNewRequestScope(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	s := Unconfigured("apns")
	for i := 0; i < 2; i++ {
		ctx := WithRequestScope(context.Background())
		s.Send(ctx, []Message{{Token: "t", Kind: KindWake, Payload: "c"}})
	}

	got := strings.Count(buf.String(), "apns not configured")
	if got != 2 {
		t.Errorf("logged %d times across 2 separate request scopes, want exactly 2 (one each)", got)
	}
}

// A different platform's Unconfigured sender gets its own dedupe entry within the same
// request scope, so an iOS and an Android rejection in one request both still surface.
func TestUnconfiguredLogsSeparatelyPerPlatformInOneScope(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	ctx := WithRequestScope(context.Background())
	Unconfigured("fcm").Send(ctx, []Message{{Token: "t", Kind: KindWake, Payload: "c"}})
	Unconfigured("apns").Send(ctx, []Message{{Token: "t", Kind: KindWake, Payload: "c"}})

	if got := strings.Count(buf.String(), "fcm not configured"); got != 1 {
		t.Errorf("fcm logged %d times, want 1", got)
	}
	if got := strings.Count(buf.String(), "apns not configured"); got != 1 {
		t.Errorf("apns logged %d times, want 1", got)
	}
}
