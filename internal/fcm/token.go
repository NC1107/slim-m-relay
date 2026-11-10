// SPDX-License-Identifier: Apache-2.0

package fcm

import (
	"context"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// tokenFailureBackoff is how long a failed token fetch is remembered, so a blackholed
// OAuth endpoint costs one 15-second fetch per window instead of one per message.
const tokenFailureBackoff = 5 * time.Second

// tokenGate hands every concurrent caller the same access token and runs at most one
// fetch at a time. oauth2.TokenSource.Token() takes no context and holds its own mutex for
// the whole refresh, so a goroutine per caller would park behind it, one more per message,
// for as long as the token endpoint stays unreachable. The zero value is ready to use.
type tokenGate struct {
	mu       sync.Mutex
	tok      *oauth2.Token
	flight   *tokenFlight
	failure  error
	failedAt time.Time
}

type tokenFlight struct {
	done chan struct{}
	tok  *oauth2.Token
	err  error
}

// token returns a valid access token from src, bounded by ctx. When ctx wins the race the
// fetch carries on without it and its result serves the next caller; it cannot outlive the
// http.Client timeout New configures, and no second fetch starts while it runs.
func (g *tokenGate) token(ctx context.Context, src oauth2.TokenSource) (*oauth2.Token, error) {
	g.mu.Lock()
	if g.tok.Valid() {
		defer g.mu.Unlock()
		return g.tok, nil
	}
	if g.failure != nil && time.Since(g.failedAt) < tokenFailureBackoff {
		defer g.mu.Unlock()
		return nil, g.failure
	}
	f := g.flight
	if f == nil {
		f = &tokenFlight{done: make(chan struct{})}
		g.flight = f
		go g.fetch(src, f)
	}
	g.mu.Unlock()

	select {
	case <-f.done:
		return f.tok, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *tokenGate) fetch(src oauth2.TokenSource, f *tokenFlight) {
	f.tok, f.err = src.Token()
	g.mu.Lock()
	g.flight = nil
	if f.err != nil {
		g.failure, g.failedAt = f.err, time.Now()
	} else {
		g.tok, g.failure = f.tok, nil
	}
	g.mu.Unlock()
	close(f.done)
}
