// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// totalChanges is the number of rows this store's one connection has written, so a test can
// tell a path that touched the database from one that only read it.
func totalChanges(t *testing.T, s *Store) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRow(`SELECT total_changes()`).Scan(&n); err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	return n
}

func refs(platform string, tokens ...string) []TokenRef {
	out := make([]TokenRef, len(tokens))
	for i, tok := range tokens {
		out[i] = TokenRef{Platform: platform, Token: tok}
	}
	return out
}

func TestBindTokensDecidesEachTokenAndCommitsTheRest(t *testing.T) {
	s := openTemp(t)
	a, b := twoKeys(t, s)
	ctx := context.Background()

	got, err := s.BindTokens(ctx, a, refs("ios", "t1", "t2", "t3"), BindLimits{MaxPerKey: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != nil || got[1] != nil || !errors.Is(got[2], ErrTokenLimit) {
		t.Fatalf("outcomes = %v, want nil, nil, ErrTokenLimit", got)
	}

	got, err = s.BindTokens(ctx, b, refs("ios", "t1", "t9"), BindLimits{MaxKeysPerToken: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(got[0], ErrTokenKeyLimit) || got[1] != nil {
		t.Fatalf("outcomes = %v, want ErrTokenKeyLimit for the held token and nil for the free one", got)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("bindings = %d (%v), want t1 and t2 for A plus t9 for B", n, err)
	}
}

func TestBindTokensOfARevokedKeyBindsNothing(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, _ := s.Issue(ctx, "", 0)
	k, _ := s.Verify(ctx, plain)
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.BindTokens(ctx, k.ID, refs("ios", "t1", "t2"), BindLimits{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("BindTokens after revoke = %v, want ErrNotFound", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bindings = %d (%v), want 0", n, err)
	}
}

func TestBindTokensBindsADuplicateOnce(t *testing.T) {
	s := openTemp(t)
	a, _ := twoKeys(t, s)

	got, err := s.BindTokens(context.Background(), a, refs("ios", "dup", "dup"), BindLimits{MaxPerKey: 1})
	if err != nil || got[0] != nil || got[1] != nil {
		t.Fatalf("outcomes = %v err %v, want both nil: the second sees the first's binding", got, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("bindings = %d (%v), want 1", n, err)
	}
}

// Each stamp write is an fsync'd commit on the relay's one connection, so a binding that was
// refreshed moments ago must be left alone instead of rewritten on every message.
func TestRebindingFreshBindingsWritesNothing(t *testing.T) {
	s := openTemp(t)
	a, _ := twoKeys(t, s)
	ctx := context.Background()
	var tokens []string
	for i := 0; i < 100; i++ {
		tokens = append(tokens, fmt.Sprintf("tok-%d", i))
	}
	if _, err := s.BindTokens(ctx, a, refs("android", tokens...), BindLimits{}); err != nil {
		t.Fatal(err)
	}

	before := totalChanges(t, s)
	if _, err := s.BindTokens(ctx, a, refs("android", tokens...), BindLimits{}); err != nil {
		t.Fatal(err)
	}
	if after := totalChanges(t, s); after != before {
		t.Fatalf("rebinding 100 fresh bindings wrote %d rows, want 0", after-before)
	}

	stale := time.Now().Add(-2 * stampInterval).Unix()
	if _, err := s.db.Exec(`UPDATE tokens SET last_seen_at = ? WHERE token = 'tok-7'`, stale); err != nil {
		t.Fatal(err)
	}
	before = totalChanges(t, s)
	if _, err := s.BindTokens(ctx, a, refs("android", tokens...), BindLimits{}); err != nil {
		t.Fatal(err)
	}
	if after := totalChanges(t, s); after-before != 1 {
		t.Fatalf("rebinding with one stale binding wrote %d rows, want exactly that one", after-before)
	}
	var seen int64
	if err := s.db.QueryRow(`SELECT last_seen_at FROM tokens WHERE token = 'tok-7'`).Scan(&seen); err != nil || seen <= stale {
		t.Fatalf("stale binding last_seen_at = %d (%v), want it refreshed past %d", seen, err, stale)
	}
}

func TestVerifyStampsLastUsedOncePerInterval(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, _ := s.Issue(ctx, "", 0)
	k, err := s.Verify(ctx, plain)
	if err != nil || k.LastUsedAt == nil {
		t.Fatalf("first verify = %+v, %v, want a stamped key", k, err)
	}

	before := totalChanges(t, s)
	for i := 0; i < 20; i++ {
		if _, err := s.Verify(ctx, plain); err != nil {
			t.Fatal(err)
		}
	}
	if after := totalChanges(t, s); after != before {
		t.Fatalf("20 verifies inside the interval wrote %d rows, want 0", after-before)
	}

	stale := time.Now().Add(-2 * stampInterval).Unix()
	if _, err := s.db.Exec(`UPDATE keys SET last_used_at = ?`, stale); err != nil {
		t.Fatal(err)
	}
	k, err = s.Verify(ctx, plain)
	if err != nil || k.LastUsedAt.Unix() <= stale {
		t.Fatalf("verify with a stale stamp = %+v, %v, want the stamp refreshed", k, err)
	}
}

func TestVerifyRefusesARevokedKeyWhoseStampIsFresh(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	plain, _ := s.Issue(ctx, "", 0)
	k, _ := s.Verify(ctx, plain)
	if err := s.Revoke(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, plain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verify of a revoked key with a fresh stamp = %v, want ErrNotFound", err)
	}
}
