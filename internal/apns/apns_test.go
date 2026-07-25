// SPDX-License-Identifier: Apache-2.0

package apns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sideshow/apns2"

	"github.com/nc1107/slim-m-relay/internal/push"
)

// fakeClient records what it was asked to push and returns a canned response, so Send can
// be exercised without real APNs credentials or a network call.
type fakeClient struct {
	resp *apns2.Response
	err  error
	got  []*apns2.Notification
}

func (f *fakeClient) PushWithContext(_ apns2.Context, n *apns2.Notification) (*apns2.Response, error) {
	f.got = append(f.got, n)
	return f.resp, f.err
}

func TestSendMapsResponseToStatus(t *testing.T) {
	tests := []struct {
		name string
		resp *apns2.Response
		err  error
		want push.Status
	}{
		{"delivered", &apns2.Response{StatusCode: 200}, nil, push.StatusDelivered},
		{"unregistered token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonUnregistered}, nil, push.StatusUnregistered},
		{"bad device token", &apns2.Response{StatusCode: 400, Reason: apns2.ReasonBadDeviceToken}, nil, push.StatusUnregistered},
		{"expired token", &apns2.Response{StatusCode: 410, Reason: apns2.ReasonExpiredToken}, nil, push.StatusUnregistered},
		{"other rejection", &apns2.Response{StatusCode: 403, Reason: apns2.ReasonForbidden}, nil, push.StatusError},
		{"transport error", nil, errors.New("boom"), push.StatusError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeClient{resp: tt.resp, err: tt.err}
			s := &Sender{client: fc, bundleID: "com.example.app"}
			results := s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindWake, Payload: "cipher"}})
			if len(results) != 1 || results[0].Status != tt.want {
				t.Fatalf("results = %+v, want status %v", results, tt.want)
			}
		})
	}
}

// Every kind except "call" takes the plain background wake: the bundle id as topic,
// PushTypeBackground, and low priority.
func TestSendUsesBundleIDAsTopicAndBackgroundPushType(t *testing.T) {
	for _, kind := range []push.Kind{push.KindMessage, push.KindMention, push.KindWake} {
		t.Run(string(kind), func(t *testing.T) {
			fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
			s := &Sender{client: fc, bundleID: "com.example.app"}
			s.Send(context.Background(), []push.Message{{Token: "tok", Kind: kind, Payload: "cipher"}})

			if len(fc.got) != 1 {
				t.Fatalf("got %d notifications, want 1", len(fc.got))
			}
			n := fc.got[0]
			if n.Topic != "com.example.app" {
				t.Errorf("topic = %q, want the configured bundle id", n.Topic)
			}
			if n.PushType != apns2.PushTypeBackground {
				t.Errorf("push type = %q, want background", n.PushType)
			}
			if n.Priority != apns2.PriorityLow {
				t.Errorf("priority = %d, want PriorityLow (a background push must not use high priority)", n.Priority)
			}
		})
	}
}

// A "call" kind must ring the device: it takes the separate ".voip" PushKit topic,
// PushTypeVOIP, and high priority, derived from the one configured bundle id rather than a
// second operator-supplied value.
func TestSendCallKindUsesVoipTopicAndPushType(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindCall, Payload: "cipher"}})

	if len(fc.got) != 1 {
		t.Fatalf("got %d notifications, want 1", len(fc.got))
	}
	n := fc.got[0]
	if n.Topic != "com.example.app.voip" {
		t.Errorf("topic = %q, want the bundle id with .voip appended", n.Topic)
	}
	if n.PushType != apns2.PushTypeVOIP {
		t.Errorf("push type = %q, want voip", n.PushType)
	}
	if n.Priority != apns2.PriorityHigh {
		t.Errorf("priority = %d, want PriorityHigh (10) for a call push", n.Priority)
	}
}

// The payload must never carry a plaintext alert, sound, or badge - only the
// content-available background flag and the opaque, already-encrypted fields.
func TestSendPayloadIsContentFree(t *testing.T) {
	fc := &fakeClient{resp: &apns2.Response{StatusCode: 200}}
	s := &Sender{client: fc, bundleID: "com.example.app"}
	s.Send(context.Background(), []push.Message{{Token: "tok", Kind: push.KindMention, Payload: "opaque-ciphertext"}})

	raw, err := json.Marshal(fc.got[0].Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, "alert") {
		t.Errorf("payload must never contain an alert:\n%s", body)
	}
	var decoded struct {
		Aps struct {
			ContentAvailable int `json:"content-available"`
			MutableContent   int `json:"mutable-content"`
		} `json:"aps"`
		Kind    string `json:"kind"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.Aps.ContentAvailable != 1 {
		t.Errorf("content-available = %d, want 1", decoded.Aps.ContentAvailable)
	}
	if decoded.Kind != "mention" {
		t.Errorf("kind = %q, want mention", decoded.Kind)
	}
	if decoded.Payload != "opaque-ciphertext" {
		t.Errorf("payload = %q, want the opaque ciphertext forwarded untouched", decoded.Payload)
	}
}
