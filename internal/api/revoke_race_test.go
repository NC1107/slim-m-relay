// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// revokeOnRead revokes the key the first time the handler reads the body, which is after the
// handler verified the key and before it binds any token: the race a concurrent admin
// revoke produces, made deterministic.
type revokeOnRead struct {
	body   io.Reader
	once   sync.Once
	revoke func()
}

func (b *revokeOnRead) Read(p []byte) (int, error) {
	b.once.Do(b.revoke)
	return b.body.Read(p)
}

func TestSendRevokedMidRequestBindsNothingAndDispatchesNothing(t *testing.T) {
	rig := newTokenRig(t, defaultCfg())
	ctx := context.Background()
	plain := rig.newKey(t)
	k, err := rig.store.Verify(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"messages":[{"platform":"android","token":"tok-a","kind":"wake"},{"platform":"android","token":"tok-b","kind":"wake"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/send", &revokeOnRead{
		body:   strings.NewReader(body),
		revoke: func() { _ = rig.store.Revoke(ctx, k.ID) },
	})
	req.Header.Set("Authorization", "Bearer "+plain)
	rr := httptest.NewRecorder()
	rig.srv.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a key revoked mid-request (body %s)", rr.Code, rr.Body.String())
	}
	if len(rig.android.got) != 0 {
		t.Errorf("a revoked key still pushed: %+v", rig.android.got)
	}
	if n := countBoundTokens(t, rig.dbPath); n != 0 {
		t.Errorf("tokens rows = %d, want 0: a revoked key must not re-create bindings", n)
	}
}
