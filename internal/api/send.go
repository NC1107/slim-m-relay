// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

type sendReq struct {
	Messages []sendMessage `json:"messages"`
}

// sendMessage is content-free by construction: it carries only what routes and wakes a
// device, never anything the relay could read. Payload is the home server's
// already-encrypted blob, forwarded untouched.
type sendMessage struct {
	Platform string `json:"platform"` // "ios" or "android"
	Token    string `json:"token"`
	Kind     string `json:"kind"`    // "message", "mention", "call", or "wake"
	Payload  string `json:"payload"` // opaque, already-encrypted; the relay never inspects it
}

type sendResp struct {
	Results []push.Result `json:"results"`
}

// maxPayloadBytes bounds one message's opaque payload. 4096 matches APNs' own remote
// notification payload ceiling, the tighter of the two providers' limits.
const maxPayloadBytes = 4096

// pending tracks where in the response a platform-specific send's result belongs, so
// results can be assembled per-provider and then scattered back into the caller's original
// order.
type pending struct {
	resultIdx int
	msg       push.Message
}

// handleSend forwards a batch of notifications to APNs or FCM, per message, on behalf of a
// registered server. The caller authenticates with its registration key, is rate-limited
// per key, and gets back one result per token so it can prune tokens the provider reports
// as dead. Every device token is bound to whichever key first sends to it (see
// internal/keys); a send for someone else's token is rejected rather than forwarded. The
// relay never logs tokens or payload content - only counts and the key id.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	plain := bearerToken(r)
	if plain == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer key")
		return
	}
	k, err := s.keys.Verify(r.Context(), plain)
	if err != nil {
		if err == keys.ErrNotFound {
			writeErr(w, http.StatusUnauthorized, "invalid or revoked key")
			return
		}
		log.Printf("relay: verify key: %v", err)
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	if !s.sendLim.Allow(strconv.FormatInt(k.ID, 10)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var req sendReq
	if err := decodeJSON(w, r, &req, 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Messages) > s.cfg.MaxMessages {
		writeErr(w, http.StatusBadRequest, "too many messages in one request")
		return
	}

	results := make([]push.Result, 0, len(req.Messages))
	var iosPending, androidPending []pending

	for _, m := range req.Messages {
		if m.Token == "" {
			continue
		}
		if len(m.Payload) > maxPayloadBytes {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		platform, ok := parsePlatform(m.Platform)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		kind, ok := parseKind(m.Kind)
		if !ok {
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		owner, err := s.keys.BindToken(r.Context(), k.ID, string(platform), m.Token)
		if err != nil {
			log.Printf("relay: bind token: %v", err)
			results = append(results, push.Result{Token: m.Token, Status: push.StatusError})
			continue
		}
		if owner != k.ID {
			// Harassment-hardening: this token belongs to a different registered server.
			results = append(results, push.Result{Token: m.Token, Status: push.StatusForbidden})
			continue
		}

		idx := len(results)
		results = append(results, push.Result{}) // filled in by dispatch below
		item := pending{resultIdx: idx, msg: push.Message{Token: m.Token, Kind: kind, Payload: m.Payload}}
		switch platform {
		case push.PlatformIOS:
			iosPending = append(iosPending, item)
		case push.PlatformAndroid:
			androidPending = append(androidPending, item)
		}
	}

	dispatch(r.Context(), s.ios, iosPending, results)
	dispatch(r.Context(), s.android, androidPending, results)

	delivered, unregistered, forbidden, failed := tally(results)
	log.Printf("relay: send key=%d n=%d delivered=%d unregistered=%d forbidden=%d error=%d",
		k.ID, len(results), delivered, unregistered, forbidden, failed)
	writeJSON(w, http.StatusOK, sendResp{Results: results})
}

// dispatch sends every pending message for one platform through sender and scatters each
// push.Result back into its original slot in results. A no-op when items is empty, so a
// batch with only one platform never touches the other provider.
func dispatch(ctx context.Context, sender push.Sender, items []pending, results []push.Result) {
	if len(items) == 0 {
		return
	}
	msgs := make([]push.Message, len(items))
	for i, p := range items {
		msgs[i] = p.msg
	}
	out := sender.Send(ctx, msgs)
	for i, p := range items {
		if i < len(out) {
			results[p.resultIdx] = out[i]
		}
	}
}

func parsePlatform(s string) (push.Platform, bool) {
	switch push.Platform(s) {
	case push.PlatformIOS, push.PlatformAndroid:
		return push.Platform(s), true
	default:
		return "", false
	}
}

func parseKind(s string) (push.Kind, bool) {
	switch push.Kind(s) {
	case push.KindMessage, push.KindMention, push.KindCall, push.KindWake:
		return push.Kind(s), true
	default:
		return "", false
	}
}
