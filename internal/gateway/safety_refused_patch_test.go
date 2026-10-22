package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/provider"
)

func TestSafetyRefused(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"filter", 400, `{"error":{"message":"safety filter: refusal"}}`, true},
		{"policy", 400, `{"error":{"message":"cyber_policy"}}`, true},
		{"access", 400, `{"error":{"message":"apply for Daybreak access"}}`, true},
		{"escaped", 400, `{"error":{"message":"safety\u0020filter: cyber\u005fpolicy"}}`, true},
		{"plain", 400, `{"error":{"message":"bad request"}}`, false},
		{"forbidden", 403, `safety filter: cyber_policy`, false},
		{"rate", 429, `Daybreak access`, false},
		{"passing", 200, `safety filter: cyber_policy`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := safetyRefused(tt.status, []byte(tt.body)); got != tt.want {
				t.Fatalf("safetyRefused(%d, %q) = %v; want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

// a safety refusal follows the request's content, so repeated refusals
// leave both the account and its model ready and count no failures.
func TestSafetyRefusalRestsNobody(t *testing.T) {
	s := &Server{}
	c := candidate{p: provider.Provider{ID: "codex", Account: &provider.Account{Agent: "codex", User: "safety@x.com"}}, model: "gpt-6.1-sol", rest: "codex#safety@x.com"}
	id := c.restKey()
	t.Cleanup(func() {
		clearRest(id)
		clearRest(c.restID())
		routed.Lock()
		delete(routed.failures, id)
		delete(routed.failures, c.restID())
		routed.Unlock()
	})
	body := []byte(`gpt-6.1-sol refused this request (safety filter: cyber_policy — This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. If you're doing authorized security work that requires more cyber permissive safeguards, apply for Daybreak access via https://platform.openai.com/settings/organization/status-and-access bef…) via Codex`)

	for i := 0; i < 5; i++ {
		r := s.restAfter(c, 400, http.Header{}, body)
		if r.By != "off" || r.Until.After(time.Now()) || resting(c) {
			t.Fatalf("safety refusal #%d rests by %s until %v; want off and ready", i+1, r.By, r.Until)
		}
	}
	routed.Lock()
	n, model := routed.failures[id], routed.failures[c.restID()]
	routed.Unlock()
	if n != 0 || model != 0 {
		t.Fatalf("safety refusal counted %d account and %d model failures; want 0", n, model)
	}
}

// the same 400 without the safety filter's words is still an unknown
// failure: it rests on the backoff ladder as before.
func TestPlain400StillRests(t *testing.T) {
	s := &Server{}
	c := candidate{p: provider.Provider{ID: "safety-plain"}, model: "gpt-6.1-sol", rest: "safety-plain#k"}
	t.Cleanup(func() {
		clearRest(c.restKey())
		clearRest(c.restID())
		routed.Lock()
		delete(routed.failures, c.restKey())
		delete(routed.failures, c.restID())
		routed.Unlock()
	})
	body := []byte(`{"error":{"message":"bad request","type":"invalid_request_error"}}`)

	r := s.restAfter(c, 400, http.Header{}, body)
	if r.By != "backoff" || time.Until(r.Until) <= 0 {
		t.Fatalf("plain 400 rests by %s until %v; want backoff", r.By, r.Until)
	}
}
