// SPDX-License-Identifier: Apache-2.0

// Package keys stores the registration keys the relay hands out, and the device-token
// bindings that keep one self-hosted server from harassing another server's devices. Only
// a SHA-256 hash of each key is kept, so a leak of the database never yields a usable key.
// SQLite (pure-Go modernc driver) keeps the relay a single container with no extra
// database to run.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// keyPrefix makes an issued key recognisable in logs and configs without revealing it.
const keyPrefix = "smr_"

// ErrNotFound is returned for an unknown, or revoked, key.
var ErrNotFound = errors.New("key not found")

// Key is one issued registration key. It never carries the plaintext or the hash. Label is
// the public URL the registrant claimed, kept unverified purely to help an admin tell keys
// apart.
type Key struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Store is the SQLite-backed key store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the key store at path and applies its schema.
func Open(path string) (*Store, error) {
	// busy_timeout lets a writer wait rather than fail under contention; WAL keeps reads
	// from blocking the occasional write; temp_store=MEMORY avoids needing a writable temp
	// dir, which the distroless runtime image does not provide.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc/sqlite serialises writes on one connection cleanly; a small pool avoids
	// "database is locked" without extra coordination, and lets BindToken's read-then-write
	// stay race-free without needing SQLite-level locking of its own.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS keys (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash     TEXT NOT NULL UNIQUE,
	label        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER,
	revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	platform   TEXT NOT NULL,
	token      TEXT NOT NULL,
	key_id     INTEGER NOT NULL REFERENCES keys(id),
	created_at INTEGER NOT NULL,
	UNIQUE(platform, token)
);`)
	return err
}

// Issue mints a new key, stores only its hash, and returns the plaintext once. The
// plaintext is unrecoverable afterward. label is an unverified admin hint (the claimed
// public URL).
func (s *Store) Issue(ctx context.Context, label string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plain := keyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO keys (key_hash, label, created_at) VALUES (?, ?, ?)`,
		hashKey(plain), label, time.Now().Unix()); err != nil {
		return "", err
	}
	return plain, nil
}

// Verify returns the key for a plaintext secret if it exists and is not revoked, stamping
// its last-used time. Returns ErrNotFound for an unknown or revoked key.
func (s *Store) Verify(ctx context.Context, plain string) (*Key, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys WHERE key_hash = ?`,
		hashKey(plain))
	k, err := scanKey(row)
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, ErrNotFound
	}
	// Stamp last-used and reflect it in the returned key, so the caller sees the value it
	// just wrote rather than the pre-update state scanned above.
	used := time.Now()
	if _, err := s.db.ExecContext(ctx, `UPDATE keys SET last_used_at = ? WHERE id = ?`, used.Unix(), k.ID); err == nil {
		t := time.Unix(used.Unix(), 0)
		k.LastUsedAt = &t
	}
	return k, nil
}

// List returns every issued key, newest first, for the admin view.
func (s *Store) List(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// Revoke marks a key unusable. Returns ErrNotFound if no such (unrevoked) key exists.
func (s *Store) Revoke(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// BindToken enforces harassment-hardening: a device push token is bound, per platform, to
// whichever key first sends to it, and every later send for that token must come from the
// same key. It returns the id of the key that owns the token - keyID itself on a fresh
// binding, or the original owner if the token was already claimed by someone else - so the
// caller can compare the two and reject a mismatch without a second round trip.
//
// The read-then-write here is race-free because Open sets SetMaxOpenConns(1): the whole
// relay shares one connection, so this transaction can never interleave with another.
func (s *Store) BindToken(ctx context.Context, keyID int64, platform, token string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var owner int64
	err = tx.QueryRowContext(ctx,
		`SELECT key_id FROM tokens WHERE platform = ? AND token = ?`, platform, token).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tokens (platform, token, key_id, created_at) VALUES (?, ?, ?, ?)`,
			platform, token, keyID, time.Now().Unix()); err != nil {
			return 0, err
		}
		owner = keyID
	case err != nil:
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return owner, nil
}

func hashKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(r rowScanner) (*Key, error) {
	var (
		k        Key
		created  int64
		lastUsed sql.NullInt64
		revoked  sql.NullInt64
	)
	if err := r.Scan(&k.ID, &k.Label, &created, &lastUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0)
	if lastUsed.Valid {
		t := time.Unix(lastUsed.Int64, 0)
		k.LastUsedAt = &t
	}
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		k.RevokedAt = &t
	}
	return &k, nil
}
