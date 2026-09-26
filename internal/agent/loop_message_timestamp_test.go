package agent

import (
	"regexp"
	"testing"
	"time"
)

var timestampPrefixRE = regexp.MustCompile(`^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2} [+-]\d{2}:\d{2}\] `)

// TestStampUserMessage_DefaultTimezone verifies the current user message is
// prefixed with a local-time timestamp in the requested IANA timezone.
func TestStampUserMessage_DefaultTimezone(t *testing.T) {
	got := stampUserMessage("hello", "Asia/Ho_Chi_Minh")

	if !timestampPrefixRE.MatchString(got) {
		t.Fatalf("expected timestamp prefix, got %q", got)
	}
	if got[len(got)-len("hello"):] != "hello" {
		t.Fatalf("expected original message preserved, got %q", got)
	}

	loc, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	want := time.Now().In(loc).Format("[2006-01-02 15:04")
	if got[:len(want)] != want {
		t.Fatalf("expected prefix %q, got %q", want, got)
	}
}

// TestStampUserMessage_FallsBackToUTC verifies an empty or invalid timezone
// falls back to UTC instead of failing or defaulting to the host's local zone.
func TestStampUserMessage_FallsBackToUTC(t *testing.T) {
	for _, tz := range []string{"", "Not/A_Real_Zone"} {
		got := stampUserMessage("hi", tz)
		want := time.Now().UTC().Format("[2006-01-02 15:04 -07:00] ") + "hi"
		if got != want {
			t.Fatalf("tz=%q: expected %q, got %q", tz, want, got)
		}
	}
}

// TestStampUserMessage_EmptyMessageUntouched verifies bootstrap/flush calls
// with an empty message never receive a stamp.
func TestStampUserMessage_EmptyMessageUntouched(t *testing.T) {
	if got := stampUserMessage("", "UTC"); got != "" {
		t.Fatalf("expected empty string untouched, got %q", got)
	}
}
