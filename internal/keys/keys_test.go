// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIssueThenVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, err := s.Issue(ctx, "https://alpha.example.com")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(plain, keyPrefix) {
		t.Errorf("issued key %q lacks the %q prefix", plain, keyPrefix)
	}
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Label != "https://alpha.example.com" {
		t.Errorf("got label=%q", k.Label)
	}
	if k.LastUsedAt == nil {
		t.Error("verify should stamp last-used")
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Verify(context.Background(), "smr_not-a-real-key"); err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokeBlocksVerify(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	plain, _ := s.Issue(ctx, "")
	k, err := s.Verify(ctx, plain)
	if err != nil {
		t.Fatalf("verify before revoke: %v", err)
	}
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Verify(ctx, plain); err != ErrNotFound {
		t.Errorf("a revoked key should verify as ErrNotFound, got %v", err)
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	s := openTemp(t)
	if err := s.Revoke(context.Background(), 9999); err != ErrNotFound {
		t.Errorf("want ErrNotFound revoking a missing key, got %v", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	_, _ = s.Issue(ctx, "first")
	_, _ = s.Issue(ctx, "second")

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 keys, got %d", len(list))
	}
	if list[0].Label != "second" {
		t.Errorf("want newest (second) first, got %q", list[0].Label)
	}
}

func TestDistinctKeysHashDistinctly(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	a, _ := s.Issue(ctx, "")
	b, _ := s.Issue(ctx, "")
	if a == b {
		t.Fatal("two issued keys must differ")
	}
	ka, _ := s.Verify(ctx, a)
	kb, _ := s.Verify(ctx, b)
	if ka.ID == kb.ID {
		t.Error("distinct keys must map to distinct rows")
	}
}

// TestBindToken exercises the harassment-hardening rule end to end: a token is bound to
// whichever key first claims it, later sends from that same key keep working, sends from a
// different key are rejected (the original owner is reported back, not the challenger), and
// the same raw token string on a different platform is an entirely separate binding.
//
// The cases build on each other's state and must run in the order given, unlike a typical
// independent table-driven test - each row is a step in one scenario against one store.
func TestBindToken(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	keyA, _ := s.Issue(ctx, "server-a")
	keyB, _ := s.Issue(ctx, "server-b")
	ka, err := s.Verify(ctx, keyA)
	if err != nil {
		t.Fatalf("verify key A: %v", err)
	}
	kb, err := s.Verify(ctx, keyB)
	if err != nil {
		t.Fatalf("verify key B: %v", err)
	}

	tests := []struct {
		name     string
		platform string
		token    string
		keyID    int64
		want     int64
	}{
		{"first claim by A establishes ownership", "ios", "device-token-1", ka.ID, ka.ID},
		{"A sending again to its own token stays fine", "ios", "device-token-1", ka.ID, ka.ID},
		{"B sending to A's token is rejected; A stays owner", "ios", "device-token-1", kb.ID, ka.ID},
		{"same raw token string on Android is a separate binding, owned by B", "android", "device-token-1", kb.ID, kb.ID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, err := s.BindToken(ctx, tt.keyID, tt.platform, tt.token)
			if err != nil {
				t.Fatalf("bind token: %v", err)
			}
			if owner != tt.want {
				t.Errorf("owner = %d, want %d", owner, tt.want)
			}
		})
	}
}

func TestBindTokenIndependentTokensDoNotInterfere(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	keyA, _ := s.Issue(ctx, "")
	keyB, _ := s.Issue(ctx, "")
	ka, _ := s.Verify(ctx, keyA)
	kb, _ := s.Verify(ctx, keyB)

	if owner, err := s.BindToken(ctx, ka.ID, "ios", "tok-a"); err != nil || owner != ka.ID {
		t.Fatalf("bind tok-a to A: owner=%d err=%v", owner, err)
	}
	if owner, err := s.BindToken(ctx, kb.ID, "ios", "tok-b"); err != nil || owner != kb.ID {
		t.Fatalf("bind tok-b to B: owner=%d err=%v", owner, err)
	}
	// Neither binding should have disturbed the other.
	if owner, err := s.BindToken(ctx, kb.ID, "ios", "tok-a"); err != nil || owner != ka.ID {
		t.Errorf("tok-a should still be owned by A, got owner=%d err=%v", owner, err)
	}
	if owner, err := s.BindToken(ctx, ka.ID, "ios", "tok-b"); err != nil || owner != kb.ID {
		t.Errorf("tok-b should still be owned by B, got owner=%d err=%v", owner, err)
	}
}
