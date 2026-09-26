package slack

import (
	"encoding/json"
	"testing"

	"github.com/slack-go/slack/slackevents"

	"github.com/nextlevelbuilder/goclaw/internal/config"
)

func TestIsAllowedDownloadHost(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected bool
	}{
		{
			name:     "valid slack.com domain",
			rawURL:   "https://files.slack.com/path/to/file",
			expected: true,
		},
		{
			name:     "valid slack-edge.com domain",
			rawURL:   "https://a.b.slack-edge.com/x/y/z",
			expected: true,
		},
		{
			name:     "valid slack-files.com domain",
			rawURL:   "https://files.slack-files.com/path/to/file",
			expected: true,
		},
		{
			name:     "http instead of https",
			rawURL:   "http://files.slack.com/path",
			expected: false,
		},
		{
			name:     "non-slack domain",
			rawURL:   "https://evil.com/malicious",
			expected: false,
		},
		{
			name:     "slack in subdomain but different tld",
			rawURL:   "https://files.slack.org/path",
			expected: false,
		},
		{
			name:     "slack.com but with subdomain not in allowlist",
			rawURL:   "https://notfiles.slack.com/path",
			expected: true, // matches .slack.com suffix
		},
		{
			name:     "slack-edge.com variations",
			rawURL:   "https://cdn.slack-edge.com/file",
			expected: true,
		},
		{
			name:     "empty string",
			rawURL:   "",
			expected: false,
		},
		{
			name:     "invalid url",
			rawURL:   "not a url at all",
			expected: false,
		},
		{
			name:     "hostname with special chars",
			rawURL:   "https://a]b.slack-edge.com/x",
			expected: true, // Go's URL parser handles this, suffix matches
		},
		{
			name:     "domain with slack.com.evil.com",
			rawURL:   "https://slack.com.evil.com/path",
			expected: false,
		},
		{
			name:     "ftp scheme",
			rawURL:   "ftp://files.slack.com/path",
			expected: false,
		},
		{
			name:     "case insensitive hostname",
			rawURL:   "https://FILES.SLACK.COM/path",
			expected: true,
		},
		{
			name:     "multiple subdomains",
			rawURL:   "https://a.b.c.slack-files.com/file",
			expected: true,
		},
		{
			name:     "hostname with port",
			rawURL:   "https://files.slack.com:443/path",
			expected: true,
		},
		{
			name:     "url with query params",
			rawURL:   "https://files.slack.com/file?token=abc&download=true",
			expected: true,
		},
		{
			name:     "url with fragment",
			rawURL:   "https://files.slack.com/file#section",
			expected: true,
		},
		{
			name:     "very long subdomain chain",
			rawURL:   "https://very.long.subdomain.chain.slack.com/file",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowedDownloadHost(tt.rawURL)
			if got != tt.expected {
				t.Errorf("isAllowedDownloadHost(%q) = %v, want %v", tt.rawURL, got, tt.expected)
			}
		})
	}
}

func TestAppContextChangedEventParsingAndPerUserTracking(t *testing.T) {
	raw := json.RawMessage(`{
		"token": "verification-token",
		"team_id": "T123",
		"api_app_id": "A123",
		"type": "event_callback",
		"event": {
			"type": "app_context_changed",
			"context": {
				"entities": [
					{
						"type": "slack#/types/channel_id",
						"value": "C456",
						"team_id": "T123"
					}
				]
			},
			"event_ts": "1700000000.000001"
		},
		"authorizations": [
			{
				"team_id": "T123",
				"user_id": "U123",
				"is_bot": false
			}
		],
		"event_id": "Ev123",
		"event_time": 1700000000
	}`)

	event, err := slackevents.ParseEvent(raw, slackevents.OptionNoVerifyToken())
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}
	contextEvent, ok := event.InnerEvent.Data.(*appContextChangedEvent)
	if !ok {
		t.Fatalf("inner event type = %T, want *appContextChangedEvent", event.InnerEvent.Data)
	}

	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	ch.trackAppContextChanged(contextEvent, raw)

	state, ok := ch.loadAgentContext("U123")
	if !ok {
		t.Fatal("app context was not stored for the authorized user")
	}
	var trackedContext slackAppContext
	if err := json.Unmarshal(state.context, &trackedContext); err != nil {
		t.Fatalf("decode tracked context: %v", err)
	}
	if len(trackedContext.Entities) != 1 {
		t.Fatalf("tracked entity count = %d, want 1", len(trackedContext.Entities))
	}
	if metadata := ch.agentContextMetadata("U123"); metadata == "" {
		t.Fatal("tracked app context was not exposed to inbound metadata")
	}
	if _, ok := ch.loadAgentContext("U999"); ok {
		t.Fatal("app context leaked to an unrelated user")
	}
}

func TestAppHomeOpenedMessagesEventRetainsContext(t *testing.T) {
	raw := json.RawMessage(`{
		"token": "verification-token",
		"team_id": "T123",
		"api_app_id": "A123",
		"type": "event_callback",
		"event": {
			"type": "app_home_opened",
			"user": "U123",
			"channel": "D123",
			"tab": "messages",
			"context": {
				"entities": [
					{
						"type": "slack#/types/channel_id",
						"value": "C456",
						"team_id": "T123"
					}
				]
			},
			"event_ts": "1700000000.000001"
		},
		"event_id": "Ev123",
		"event_time": 1700000000
	}`)

	event, err := slackevents.ParseEvent(raw, slackevents.OptionNoVerifyToken())
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}
	homeEvent, ok := event.InnerEvent.Data.(*appHomeOpenedEvent)
	if !ok {
		t.Fatalf("inner event type = %T, want *appHomeOpenedEvent", event.InnerEvent.Data)
	}

	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	ch.trackAppHomeOpened(homeEvent)
	state, ok := ch.loadAgentContext("U123")
	if !ok {
		t.Fatal("app_home_opened messages context was not tracked")
	}
	if state.containerChannelID != "D123" {
		t.Errorf("container channel = %q, want D123", state.containerChannelID)
	}
	var trackedContext slackAppContext
	if err := json.Unmarshal(state.context, &trackedContext); err != nil {
		t.Fatalf("decode tracked context: %v", err)
	}
	if len(trackedContext.Entities) != 1 {
		t.Errorf("tracked entity count = %d, want 1", len(trackedContext.Entities))
	}
}

func TestAssistantThreadStartedSuppliesMissingMessageThread(t *testing.T) {
	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	ch.trackAssistantThread(slackevents.AssistantThread{
		UserID:          "U123",
		ChannelID:       "D123",
		ThreadTimeStamp: "1700000000.000001",
	}, "assistant_thread_started")

	if got := ch.agentThreadTS("U123", "D123", "", "1700000001.000002"); got != "1700000000.000001" {
		t.Errorf("agentThreadTS() = %q, want tracked assistant thread", got)
	}
	if got := ch.agentThreadTS("U999", "D123", "", "1700000001.000002"); got != "1700000001.000002" {
		t.Errorf("unrelated user thread = %q, want triggering message timestamp", got)
	}
}
