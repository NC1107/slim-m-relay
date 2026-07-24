// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strconv"

	"github.com/nc1107/slim-m-relay/internal/keys"
)

// requireAdmin guards the admin handlers with a constant-time comparison against the
// configured admin token, supplied as "Authorization: Bearer <token>".
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	want := []byte(s.cfg.AdminToken)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(bearerToken(r))
		if len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1 {
			next(w, r)
			return
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	}
}

// handleAdminListKeys lists every issued key (metadata only; never the secret or its hash).
func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.keys.List(r.Context())
	if err != nil {
		log.Printf("relay: list keys: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if list == nil {
		list = []keys.Key{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": list})
}

// handleAdminRevokeKey revokes a key by id so a misbehaving server can be cut off.
func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.keys.Revoke(r.Context(), id); err != nil {
		if err == keys.ErrNotFound {
			writeErr(w, http.StatusNotFound, "no such key")
			return
		}
		log.Printf("relay: revoke key: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
