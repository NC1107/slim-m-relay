// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// maxTokenBytes bounds a device token. slim-m's server already refuses to register a
// token over 1024 characters, so no real client token is longer.
const maxTokenBytes = 1024

// canonicalToken validates a device token for its platform and returns the form the relay
// binds and sends. An APNs token is spliced into the request path, so only characters that
// cannot change that path are accepted, and it is lowercased because APNs tokens are hex and
// a case variant would otherwise be a second binding for the same device. FCM tokens travel
// in a JSON body, so the Android alphabet only has to match what Firebase issues.
func canonicalToken(platform push.Platform, token string) (string, bool) {
	if token == "" || len(token) > maxTokenBytes {
		return "", false
	}
	if platform == push.PlatformIOS {
		if !onlyChars(token, isPathSafe) {
			return "", false
		}
		return strings.ToLower(token), true
	}
	return token, onlyChars(token, isFCMChar)
}

func onlyChars(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isPathSafe(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }

func isFCMChar(c byte) bool { return isPathSafe(c) || c == ':' || c == '.' }
