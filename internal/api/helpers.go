// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// writeJSON renders v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr renders a JSON {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a JSON body up to maxBytes into v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// clientIP is the caller's address. The relay always runs behind a trusted reverse proxy
// that sets X-Forwarded-For, so its first hop is the real client; a direct hit with no such
// header falls back to the socket address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// recoverer turns a handler panic into a 500 instead of crashing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("relay: recovered from panic: %v", rec)
				writeErr(w, http.StatusInternalServerError, "server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// tally counts delivery outcomes for logging, without touching tokens or payload content.
func tally(results []push.Result) (delivered, unregistered, forbidden, failed int) {
	for _, r := range results {
		switch r.Status {
		case push.StatusDelivered:
			delivered++
		case push.StatusUnregistered:
			unregistered++
		case push.StatusForbidden:
			forbidden++
		default:
			failed++
		}
	}
	return
}
