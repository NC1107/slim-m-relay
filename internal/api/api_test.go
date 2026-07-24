// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

// fakeSender records what it was asked to send and reports every token delivered, standing
// in for either platform's real provider client in tests.
type fakeSender struct {
	got []push.Message
}

func (f *fakeSender) Send(_ context.Context, msgs []push.Message) []push.Result {
	f.got = append(f.got, msgs...)
	out := make([]push.Result, len(msgs))
	for i, m := range msgs {
		out[i] = push.Result{Token: m.Token, Status: push.StatusDelivered}
	}
	return out
}

func newTestServer(t *testing.T, cfg config.Config) (*Server, *fakeSender, *fakeSender, *keys.Store) {
	t.Helper()
	store, err := keys.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ios, android := &fakeSender{}, &fakeSender{}
	srv := New(cfg, ios, android, store)
	return srv, ios, android, store
}

// defaultCfg sets limits high enough not to interfere with tests that aren't about limits.
func defaultCfg() config.Config {
	return config.Config{
		MaxMessages:     500,
		RegisterPerHour: 1000,
		RegisterBurst:   1000,
		SendPerMinute:   100000,
		SendBurst:       100000,
	}
}

func do(h http.Handler, method, target, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRegisterIssuesKey(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	rr := do(srv.Router(), http.MethodPost, "/v1/register", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp registerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Key, "smr_") {
		t.Fatalf("key %q lacks smr_ prefix", resp.Key)
	}
	k, err := store.Verify(context.Background(), resp.Key)
	if err != nil {
		t.Fatalf("issued key does not verify: %v", err)
	}
	if k.Label != "" {
		t.Errorf("a register with no publicUrl should have an empty label, got %q", k.Label)
	}
}

func TestRegisterRateLimited(t *testing.T) {
	cfg := defaultCfg()
	cfg.RegisterBurst = 1
	cfg.RegisterPerHour = 1
	srv, _, _, _ := newTestServer(t, cfg)
	h := srv.Router()

	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/register", "", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second register = %d, want 429", rr.Code)
	}
}

func TestRegisterStoresClaimedURLAsLabel(t *testing.T) {
	srv, _, _, store := newTestServer(t, defaultCfg())
	body, _ := json.Marshal(registerReq{PublicURL: "https://alpha.example.com"})
	rr := do(srv.Router(), http.MethodPost, "/v1/register", string(body), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp registerResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	k, err := store.Verify(context.Background(), resp.Key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Label != "https://alpha.example.com" {
		t.Errorf("label = %q, want the claimed public URL recorded", k.Label)
	}
}

func TestSendRequiresBearer(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	if rr := do(srv.Router(), http.MethodPost, "/v1/send", `{"messages":[]}`, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("send without bearer = %d, want 401", rr.Code)
	}
}

func TestSendRejectsUnknownKey(t *testing.T) {
	srv, _, _, _ := newTestServer(t, defaultCfg())
	rr := do(srv.Router(), http.MethodPost, "/v1/send", `{"messages":[{"platform":"ios","token":"t","kind":"wake","payload":"c"}]}`, "smr_nope")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("send with unknown key = %d, want 401", rr.Code)
	}
}

func TestSendDispatchesByPlatform(t *testing.T) {
	srv, ios, android, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "")

	body := `{"messages":[
		{"platform":"ios","token":"a","kind":"message","payload":"cipher-a"},
		{"platform":"android","token":"b","kind":"mention","payload":"cipher-b"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results = %+v, want 2", resp.Results)
	}
	for _, r := range resp.Results {
		if r.Status != push.StatusDelivered {
			t.Errorf("result %+v, want delivered", r)
		}
	}
	if len(ios.got) != 1 || ios.got[0].Token != "a" {
		t.Errorf("iOS sender got %+v, want exactly token a", ios.got)
	}
	if len(android.got) != 1 || android.got[0].Token != "b" {
		t.Errorf("Android sender got %+v, want exactly token b", android.got)
	}
}

func TestSendRejectsUnknownPlatformAndKind(t *testing.T) {
	srv, ios, android, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "")

	body := `{"messages":[
		{"platform":"windows-phone","token":"a","kind":"message","payload":"c"},
		{"platform":"ios","token":"b","kind":"not-a-real-kind","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Results) != 2 {
		t.Fatalf("results = %+v, want 2", resp.Results)
	}
	for _, r := range resp.Results {
		if r.Status != push.StatusError {
			t.Errorf("result %+v, want error", r)
		}
	}
	if len(ios.got) != 0 || len(android.got) != 0 {
		t.Error("neither provider should have been called for invalid platform/kind")
	}
}

func TestSendEnforcesTokenBinding(t *testing.T) {
	srv, ios, _, store := newTestServer(t, defaultCfg())
	keyA, _ := store.Issue(context.Background(), "server-a")
	keyB, _ := store.Issue(context.Background(), "server-b")
	h := srv.Router()

	// Server A claims the token first.
	bodyA := `{"messages":[{"platform":"ios","token":"shared-token","kind":"wake","payload":"a"}]}`
	rr := do(h, http.MethodPost, "/v1/send", bodyA, keyA)
	if rr.Code != http.StatusOK {
		t.Fatalf("A's send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var respA sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &respA)
	if len(respA.Results) != 1 || respA.Results[0].Status != push.StatusDelivered {
		t.Fatalf("A's result = %+v, want delivered", respA.Results)
	}

	// Server B tries to send to the same token: rejected, and never reaches the provider.
	bodyB := `{"messages":[{"platform":"ios","token":"shared-token","kind":"wake","payload":"b"}]}`
	rr = do(h, http.MethodPost, "/v1/send", bodyB, keyB)
	if rr.Code != http.StatusOK {
		t.Fatalf("B's send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var respB sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &respB)
	if len(respB.Results) != 1 || respB.Results[0].Status != push.StatusForbidden {
		t.Fatalf("B's result = %+v, want forbidden", respB.Results)
	}
	if len(ios.got) != 1 {
		t.Errorf("provider saw %d messages, want exactly 1 (A's, not B's)", len(ios.got))
	}
}

func TestSendRejectsOversizedBatch(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxMessages = 2
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "")

	body := `{"messages":[
		{"platform":"ios","token":"a","kind":"wake","payload":"c"},
		{"platform":"ios","token":"b","kind":"wake","payload":"c"},
		{"platform":"ios","token":"c","kind":"wake","payload":"c"}
	]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch = %d, want 400", rr.Code)
	}
}

func TestSendRejectsOversizedPayload(t *testing.T) {
	srv, ios, _, store := newTestServer(t, defaultCfg())
	key, _ := store.Issue(context.Background(), "")

	huge := strings.Repeat("x", maxPayloadBytes+1)
	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"` + huge + `"}]}`
	rr := do(srv.Router(), http.MethodPost, "/v1/send", body, key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send = %d, want 200 (body %s)", rr.Code, rr.Body)
	}
	var resp sendResp
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Results) != 1 || resp.Results[0].Status != push.StatusError {
		t.Fatalf("results = %+v, want a single error result", resp.Results)
	}
	if len(ios.got) != 0 {
		t.Error("an oversized payload must never reach the provider")
	}
}

func TestSendRateLimitedPerKey(t *testing.T) {
	cfg := defaultCfg()
	cfg.SendBurst = 1
	cfg.SendPerMinute = 1
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "")
	h := srv.Router()

	body := `{"messages":[{"platform":"ios","token":"a","kind":"wake","payload":"c"}]}`
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusOK {
		t.Fatalf("first send = %d, want 200", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second send = %d, want 429", rr.Code)
	}
}

func TestAdminRevokeStopsDelivery(t *testing.T) {
	cfg := defaultCfg()
	cfg.AdminToken = "admin-secret"
	srv, _, _, store := newTestServer(t, cfg)
	key, _ := store.Issue(context.Background(), "")
	k, _ := store.Verify(context.Background(), key)
	h := srv.Router()

	body := `{"messages":[{"platform":"android","token":"a","kind":"wake","payload":"c"}]}`
	// A send works before revocation.
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusOK {
		t.Fatalf("pre-revoke send = %d, want 200", rr.Code)
	}
	// Admin needs the token.
	if rr := do(h, http.MethodGet, "/admin/keys", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d, want 401", rr.Code)
	}
	// Revoke with the token.
	revokePath := "/admin/keys/" + strconv.FormatInt(k.ID, 10) + "/revoke"
	if rr := do(h, http.MethodPost, revokePath, "", "admin-secret"); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rr.Code)
	}
	// The key no longer sends.
	if rr := do(h, http.MethodPost, "/v1/send", body, key); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke send = %d, want 401", rr.Code)
	}
}
