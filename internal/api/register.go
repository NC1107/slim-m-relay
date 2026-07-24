// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"log"
	"net/http"
	"strings"
)

type registerReq struct {
	PublicURL string `json:"publicUrl"`
}

type registerResp struct {
	Key string `json:"key"`
}

// maxLabelLen bounds the stored public-URL label; the value is untrusted so it must not be
// able to bloat the store or the admin view.
const maxLabelLen = 256

// handleRegister mints a scoped key for a self-hosting server. It is self-serve: a server
// calls this once on first boot and stores the returned key. Registration is IP-rate-limited
// so the endpoint can't be used to mass-mint. The claimed publicUrl is recorded, unverified,
// only as a hint that helps an admin tell keys apart.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.registerLim.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many registrations from this address, try again later")
		return
	}
	var req registerReq
	// An empty body is fine: publicUrl is optional.
	if err := decodeJSON(w, r, &req, 4<<10); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	label := strings.TrimSpace(req.PublicURL)
	if len(label) > maxLabelLen {
		label = label[:maxLabelLen]
	}
	key, err := s.keys.Issue(r.Context(), label)
	if err != nil {
		log.Printf("relay: issue key: %v", err)
		writeErr(w, http.StatusInternalServerError, "could not issue key")
		return
	}
	// %q escapes control characters, so an untrusted label can't inject into the log line.
	log.Printf("relay: issued key label=%q", label)
	writeJSON(w, http.StatusOK, registerResp{Key: key})
}
