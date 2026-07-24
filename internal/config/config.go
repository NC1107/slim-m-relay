// SPDX-License-Identifier: Apache-2.0

// Package config loads the relay's runtime settings from the environment, so the service
// stays a single self-contained binary that is easy to run under Docker.
package config

import (
	"os"
	"strconv"
)

// Config holds all runtime configuration for the relay.
type Config struct {
	// Port is the TCP port the relay listens on.
	Port int
	// DBPath is the SQLite file that stores hashed keys and device-token bindings.
	DBPath string
	// AdminToken guards the /admin endpoints (list and revoke keys). Empty disables them.
	AdminToken string

	// FCMCredentialsFile points to the Firebase service-account JSON used to send Android
	// pushes. Empty is not fatal: Android sends fail clearly instead of the relay refusing
	// to start.
	FCMCredentialsFile string

	// APNsKeyPath, APNsKeyID, APNsTeamID and APNsBundleID are the token-based (.p8)
	// credentials used to send iOS pushes. All four are required together; if any is
	// empty, iOS sends fail clearly instead of the relay refusing to start.
	APNsKeyPath  string
	APNsKeyID    string
	APNsTeamID   string
	APNsBundleID string
	// APNsProduction selects APNs' production gateway. false uses the sandbox gateway,
	// which is what devices running a debug/development build register against.
	APNsProduction bool

	// RegisterPerHour and RegisterBurst bound how often one IP may mint new keys.
	RegisterPerHour int
	RegisterBurst   int
	// SendPerMinute and SendBurst bound how often one key may fan out notifications.
	SendPerMinute int
	SendBurst     int
	// MaxMessages caps how many device tokens a single /v1/send request may carry.
	MaxMessages int
}

// Load reads configuration from the environment, applying defaults that suit a single
// maintainer-run relay.
func Load() Config {
	return Config{
		Port:               getint("RELAY_PORT", 8090),
		DBPath:             getenv("RELAY_DB_PATH", "/data/relay.db"),
		AdminToken:         getenv("RELAY_ADMIN_TOKEN", ""),
		FCMCredentialsFile: getenv("RELAY_FCM_CREDENTIALS_FILE", ""),
		APNsKeyPath:        getenv("RELAY_APNS_KEY_PATH", ""),
		APNsKeyID:          getenv("RELAY_APNS_KEY_ID", ""),
		APNsTeamID:         getenv("RELAY_APNS_TEAM_ID", ""),
		APNsBundleID:       getenv("RELAY_APNS_BUNDLE_ID", ""),
		APNsProduction:     getbool("RELAY_APNS_PRODUCTION", true),
		RegisterPerHour:    getint("RELAY_REGISTER_PER_HOUR", 5),
		RegisterBurst:      getint("RELAY_REGISTER_BURST", 3),
		SendPerMinute:      getint("RELAY_SEND_PER_MINUTE", 120),
		SendBurst:          getint("RELAY_SEND_BURST", 60),
		MaxMessages:        getint("RELAY_MAX_MESSAGES", 500),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getbool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
