// SPDX-License-Identifier: Apache-2.0

// Package api wires the relay's HTTP endpoints: self-serve key registration, the
// authenticated send fan-out that dispatches by platform to APNs or FCM, a health check,
// and a token-gated admin surface.
package api

import (
	"net/http"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
	"github.com/nc1107/slim-m-relay/internal/ratelimit"
)

// Server holds dependencies shared by all handlers.
type Server struct {
	cfg         config.Config
	ios         push.Sender // APNs
	android     push.Sender // FCM
	keys        *keys.Store
	registerLim *ratelimit.Limiter
	sendLim     *ratelimit.Limiter
}

// New constructs a Server. ios and android are the platform senders /v1/send dispatches to
// by each message's declared platform; either may be a push.Unconfigured stub when the
// relay was started without that platform's credentials.
func New(cfg config.Config, ios, android push.Sender, store *keys.Store) *Server {
	return &Server{
		cfg:         cfg,
		ios:         ios,
		android:     android,
		keys:        store,
		registerLim: ratelimit.New(float64(cfg.RegisterPerHour)/60.0, cfg.RegisterBurst),
		sendLim:     ratelimit.New(float64(cfg.SendPerMinute), cfg.SendBurst),
	}
}

// Router builds the HTTP handler. Routing uses net/http's method+path patterns (Go 1.22+),
// keeping the relay free of a router dependency.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("POST /v1/send", s.handleSend)

	// Admin is only mounted when a token is configured, and every request must carry it.
	if s.cfg.AdminToken != "" {
		mux.HandleFunc("GET /admin/keys", s.requireAdmin(s.handleAdminListKeys))
		mux.HandleFunc("POST /admin/keys/{id}/revoke", s.requireAdmin(s.handleAdminRevokeKey))
	}
	return recoverer(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
