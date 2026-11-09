// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

type tokenRig struct {
	srv     *Server
	ios     *fakeSender
	android *fakeSender
	store   *keys.Store
	dbPath  string
}

func newTokenRig(t *testing.T, cfg config.Config) *tokenRig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := keys.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ios, android := &fakeSender{}, &fakeSender{}
	return &tokenRig{srv: New(cfg, ios, android, store), ios: ios, android: android, store: store, dbPath: path}
}

func (r *tokenRig) newKey(t *testing.T) string {
	t.Helper()
	plain, err := r.store.Issue(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func (r *tokenRig) send(t *testing.T, key, platform string, tokens ...string) []push.Result {
	t.Helper()
	msgs := make([]sendMessage, len(tokens))
	for i, tok := range tokens {
		msgs[i] = sendMessage{Platform: platform, Token: tok, Kind: "wake"}
	}
	body, err := json.Marshal(sendReq{Messages: msgs})
	if err != nil {
		t.Fatal(err)
	}
	rr := do(r.srv.Router(), http.MethodPost, "/v1/send", string(body), key)
	if rr.Code != http.StatusOK {
		t.Fatalf("send status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp sendResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Results
}

func TestSendRefusesTokensThatCouldRewriteTheApnsRequestPath(t *testing.T) {
	victim := strings.Repeat("ab12", 16)
	bad := []string{victim + "#1", victim + "?x=1", "x/y", victim + "%2F", "..", victim + ".x", "a b"}
	for i, tok := range bad {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			rig := newTokenRig(t, defaultCfg())
			res := rig.send(t, rig.newKey(t), "ios", tok)
			if len(res) != 1 || res[0].Status != push.StatusError {
				t.Fatalf("results = %+v, want one error", res)
			}
			if len(rig.ios.got) != 0 {
				t.Fatalf("the token reached APNs: %+v", rig.ios.got)
			}
			if n := countBoundTokens(t, rig.dbPath); n != 0 {
				t.Fatalf("tokens rows = %d, want 0", n)
			}
		})
	}
}

func TestSendRefusesAndroidTokensOutsideTheFirebaseAlphabet(t *testing.T) {
	for i, tok := range []string{"a#1", "a?b", "a/b", "a%20b", "a,b", "tok\"en"} {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			rig := newTokenRig(t, defaultCfg())
			res := rig.send(t, rig.newKey(t), "android", tok)
			if len(res) != 1 || res[0].Status != push.StatusError {
				t.Fatalf("results = %+v, want one error", res)
			}
			if n := countBoundTokens(t, rig.dbPath); n != 0 {
				t.Fatalf("tokens rows = %d, want 0", n)
			}
		})
	}
}

func TestSendLowercasesIosTokensSoCaseVariantsShareOneBindingSet(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxKeysPerToken = 2
	rig := newTokenRig(t, cfg)
	lower := strings.Repeat("ab12", 16)
	upper := strings.ToUpper(lower)
	keyA, keyB, keyC := rig.newKey(t), rig.newKey(t), rig.newKey(t)

	if res := rig.send(t, keyA, "ios", lower); res[0].Status != push.StatusDelivered {
		t.Fatalf("first key: %+v", res)
	}
	if res := rig.send(t, keyB, "ios", lower); res[0].Status != push.StatusDelivered {
		t.Fatalf("second key: %+v", res)
	}
	res := rig.send(t, keyC, "ios", upper)
	if res[0].Status != push.StatusForbidden {
		t.Fatalf("an uppercase variant of a full token = %+v, want forbidden", res)
	}
	if res[0].Token != upper {
		t.Errorf("result token = %q, want the caller's own spelling %q", res[0].Token, upper)
	}
}

func TestSendForwardsTheLowercaseIosTokenButEchoesTheCallersSpelling(t *testing.T) {
	rig := newTokenRig(t, defaultCfg())
	lower := strings.Repeat("ab12", 16)
	upper := strings.ToUpper(lower)

	res := rig.send(t, rig.newKey(t), "ios", upper)
	if res[0].Status != push.StatusDelivered || res[0].Token != upper {
		t.Fatalf("result = %+v, want delivered and echoing %q", res[0], upper)
	}
	if len(rig.ios.got) != 1 || rig.ios.got[0].Token != lower {
		t.Fatalf("provider received %+v, want the lowercase token", rig.ios.got)
	}
}
