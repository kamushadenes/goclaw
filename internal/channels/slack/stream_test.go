package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	slackapi "github.com/slack-go/slack"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/config"
)

type recordedSlackRequest struct {
	path   string
	values url.Values
}

type slackRequestRecorder struct {
	mu       sync.Mutex
	requests []recordedSlackRequest
	failures map[string]string
}

type recordedStreamChunk struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (r *slackRequestRecorder) add(req recordedSlackRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *slackRequestRecorder) snapshot() []recordedSlackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedSlackRequest(nil), r.requests...)
}

func (r *slackRequestRecorder) fail(path, apiError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[path] = apiError
}

func (r *slackRequestRecorder) failure(path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures[path]
}

func newSlackAPITestServer(t *testing.T) (*httptest.Server, *slackRequestRecorder) {
	t.Helper()
	recorder := &slackRequestRecorder{failures: make(map[string]string)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		recorder.add(recordedSlackRequest{
			path:   r.URL.Path,
			values: r.Form,
		})
		w.Header().Set("Content-Type", "application/json")
		if apiError := recorder.failure(r.URL.Path); apiError != "" {
			if err := json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": apiError,
			}); err != nil {
				t.Errorf("Encode() error = %v", err)
			}
			return
		}
		response := map[string]any{"ok": true}
		switch r.URL.Path {
		case "/chat.startStream", "/chat.appendStream", "/chat.stopStream", "/chat.postMessage":
			response["channel"] = r.Form.Get("channel")
			response["ts"] = "1700000000.000001"
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Encode() error = %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server, recorder
}

func TestExtractChannelID(t *testing.T) {
	tests := []struct {
		name     string
		localKey string
		expected string
	}{
		{
			name:     "plain channel id",
			localKey: "C123456",
			expected: "C123456",
		},
		{
			name:     "threaded message",
			localKey: "C123456:thread:1234.5678",
			expected: "C123456",
		},
		{
			name:     "threaded with different ts format",
			localKey: "C999:thread:999999.999999",
			expected: "C999",
		},
		{
			name:     "no thread marker",
			localKey: "C123456789",
			expected: "C123456789",
		},
		{
			name:     "empty string",
			localKey: "",
			expected: "",
		},
		{
			name:     "only thread marker",
			localKey: ":thread:1234.5678",
			expected: ":thread:1234.5678",
		},
		{
			name:     "colon but no thread text",
			localKey: "C123:thread:",
			expected: "C123",
		},
		{
			name:     "multiple colons",
			localKey: "C123:thread:1234:5678",
			expected: "C123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractChannelID(tt.localKey)
			if got != tt.expected {
				t.Errorf("extractChannelID(%q) = %q, want %q", tt.localKey, got, tt.expected)
			}
		})
	}
}

func TestExtractThreadTS(t *testing.T) {
	tests := []struct {
		name     string
		localKey string
		expected string
	}{
		{
			name:     "threaded message",
			localKey: "C123456:thread:1234.5678",
			expected: "1234.5678",
		},
		{
			name:     "plain channel id",
			localKey: "C123456",
			expected: "",
		},
		{
			name:     "empty string",
			localKey: "",
			expected: "",
		},
		{
			name:     "only thread marker (no channel id)",
			localKey: ":thread:1234.5678",
			expected: "", // idx must be > 0, so this returns ""
		},
		{
			name:     "thread marker but empty ts",
			localKey: "C123:thread:",
			expected: "",
		},
		{
			name:     "multiple colons after thread",
			localKey: "C123:thread:1234:5678:extra",
			expected: "1234:5678:extra",
		},
		{
			name:     "thread marker not found",
			localKey: "C123:other:1234.5678",
			expected: "",
		},
		{
			name:     "thread marker case sensitive",
			localKey: "C123:THREAD:1234.5678",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractThreadTS(tt.localKey)
			if got != tt.expected {
				t.Errorf("extractThreadTS(%q) = %q, want %q", tt.localKey, got, tt.expected)
			}
		})
	}
}

func TestStartResponseIndicatorUsesAssistantStatusInAgentMode(t *testing.T) {
	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	server, recorder := newSlackAPITestServer(t)
	ch.api = slackapi.New("xoxb-test", slackapi.OptionAPIURL(server.URL+"/"))

	const localKey = "D123:thread:1700000000.000001"
	ch.startResponseIndicator(
		context.Background(),
		"D123",
		localKey,
		"1700000000.000001",
		"U123",
		false,
	)

	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	if requests[0].path != "/assistant.threads.setStatus" {
		t.Fatalf("request path = %q, want assistant.threads.setStatus", requests[0].path)
	}
	if got := requests[0].values.Get("status"); got != "Thinking..." {
		t.Errorf("status = %q, want Thinking...", got)
	}
	if got := requests[0].values.Get("channel_id"); got != "D123" {
		t.Errorf("channel_id = %q, want D123", got)
	}
	if got := requests[0].values.Get("thread_ts"); got != "1700000000.000001" {
		t.Errorf("thread_ts = %q, want trigger timestamp", got)
	}
	if _, ok := ch.placeholders.Load(localKey); ok {
		t.Fatal("agent mode must not create a Thinking placeholder")
	}
	if _, ok := ch.loadAgentThread(localKey); !ok {
		t.Fatal("agent thread routing state was not stored")
	}
}

func TestStartResponseIndicatorKeepsLegacyPlaceholder(t *testing.T) {
	ch := newTestSlackChannel(t, config.SlackConfig{})
	server, recorder := newSlackAPITestServer(t)
	ch.api = slackapi.New("xoxb-test", slackapi.OptionAPIURL(server.URL+"/"))

	const localKey = "D123:thread:1700000000.000001"
	ch.startResponseIndicator(
		context.Background(),
		"D123",
		localKey,
		"1700000000.000001",
		"U123",
		false,
	)

	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	if requests[0].path != "/chat.postMessage" {
		t.Fatalf("request path = %q, want chat.postMessage", requests[0].path)
	}
	if got := requests[0].values.Get("text"); got != "Thinking..." {
		t.Errorf("text = %q, want Thinking...", got)
	}
	if _, ok := ch.placeholders.Load(localKey); !ok {
		t.Fatal("legacy mode must retain the Thinking placeholder")
	}
}

func TestNativeSlackStreamLifecycleAndFinalSendHandoff(t *testing.T) {
	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	server, recorder := newSlackAPITestServer(t)
	ch.api = slackapi.New("xoxb-test", slackapi.OptionAPIURL(server.URL+"/"))
	ch.SetRunning(true)

	const (
		localKey = "D123:thread:1700000000.000001"
		fullText = "Hello **world** and more"
	)
	ch.agentThreads.Store(localKey, agentThreadState{
		channelID:       "D123",
		threadTS:        "1700000000.000001",
		recipientUserID: "U123",
		updatedAt:       time.Now(),
	})

	stream, err := ch.CreateStream(context.Background(), localKey, false)
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}
	stream.Update(context.Background(), "Hello **world**")
	stream.Update(context.Background(), fullText)
	if err := stream.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	ch.FinalizeStream(context.Background(), localKey, stream)

	beforeSend := recorder.snapshot()
	if len(beforeSend) != 3 {
		t.Fatalf("request count before Send = %d, want 3", len(beforeSend))
	}
	wantPaths := []string{"/chat.startStream", "/chat.appendStream", "/chat.stopStream"}
	for i, want := range wantPaths {
		if beforeSend[i].path != want {
			t.Errorf("request[%d].path = %q, want %q", i, beforeSend[i].path, want)
		}
	}
	if got := beforeSend[0].values.Get("thread_ts"); got != "1700000000.000001" {
		t.Errorf("startStream thread_ts = %q, want trigger timestamp", got)
	}
	if got := decodeRecordedStreamChunks(t, beforeSend[0]); len(got) != 0 {
		t.Errorf("startStream initial chunks = %#v, want empty", got)
	}
	appendChunks := decodeRecordedStreamChunks(t, beforeSend[1])
	if len(appendChunks) != 1 || appendChunks[0].Type != "markdown_text" ||
		appendChunks[0].Text != "Hello **world**" {
		t.Errorf("appendStream chunks = %#v, want raw Markdown chunk", appendChunks)
	}
	stopChunks := decodeRecordedStreamChunks(t, beforeSend[2])
	if len(stopChunks) != 1 || stopChunks[0].Type != "markdown_text" ||
		stopChunks[0].Text != " and more" {
		t.Errorf("stopStream chunks = %#v, want throttled suffix chunk", stopChunks)
	}

	if err := ch.Send(context.Background(), bus.OutboundMessage{
		ChatID:  "D123",
		Content: fullText,
		Metadata: map[string]string{
			"placeholder_key":   localKey,
			"message_thread_id": "1700000000.000001",
		},
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if afterSend := recorder.snapshot(); len(afterSend) != len(beforeSend) {
		t.Fatalf("final Send emitted %d extra requests, want no duplicate message", len(afterSend)-len(beforeSend))
	}
}

func TestNativeSlackStreamFailureFallsBackToNormalMessage(t *testing.T) {
	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	server, recorder := newSlackAPITestServer(t)
	ch.api = slackapi.New("xoxb-test", slackapi.OptionAPIURL(server.URL+"/"))
	ch.SetRunning(true)

	const (
		localKey = "D123:thread:1700000000.000001"
		fullText = "Fallback **response**"
	)
	ch.agentThreads.Store(localKey, agentThreadState{
		channelID: "D123",
		threadTS:  "1700000000.000001",
		updatedAt: time.Now(),
	})
	stream, err := ch.CreateStream(context.Background(), localKey, false)
	if err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}

	recorder.fail("/chat.appendStream", "stream_closed")
	stream.Update(context.Background(), fullText)
	if err := stream.Stop(context.Background()); err == nil {
		t.Fatal("Stop() error = nil, want appendStream failure")
	}
	ch.FinalizeStream(context.Background(), localKey, stream)

	if err := ch.Send(context.Background(), bus.OutboundMessage{
		ChatID:  "D123",
		Content: fullText,
		Metadata: map[string]string{
			"placeholder_key":   localKey,
			"message_thread_id": "1700000000.000001",
		},
	}); err != nil {
		t.Fatalf("Send() fallback error = %v", err)
	}

	requests := recorder.snapshot()
	wantPaths := []string{
		"/chat.startStream",
		"/chat.appendStream",
		"/chat.stopStream",
		"/chat.delete",
		"/chat.postMessage",
	}
	if len(requests) != len(wantPaths) {
		t.Fatalf("request paths = %#v, want %#v", requestPaths(requests), wantPaths)
	}
	for i, want := range wantPaths {
		if requests[i].path != want {
			t.Errorf("request[%d].path = %q, want %q", i, requests[i].path, want)
		}
	}
}

func TestNativeSlackGroupStreamIncludesRecipient(t *testing.T) {
	enabled := true
	ch := newTestSlackChannel(t, config.SlackConfig{AgentMode: &enabled})
	server, recorder := newSlackAPITestServer(t)
	ch.api = slackapi.New("xoxb-test", slackapi.OptionAPIURL(server.URL+"/"))

	const localKey = "C123:thread:1700000000.000001"
	ch.agentThreads.Store(localKey, agentThreadState{
		channelID:       "C123",
		threadTS:        "1700000000.000001",
		recipientUserID: "U123",
		recipientTeamID: "T123",
		isGroup:         true,
		updatedAt:       time.Now(),
	})
	if _, err := ch.CreateStream(context.Background(), localKey, false); err != nil {
		t.Fatalf("CreateStream() error = %v", err)
	}

	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	if got := requests[0].values.Get("recipient_user_id"); got != "U123" {
		t.Errorf("recipient_user_id = %q, want U123", got)
	}
	if got := requests[0].values.Get("recipient_team_id"); got != "T123" {
		t.Errorf("recipient_team_id = %q, want T123", got)
	}
}

func requestPaths(requests []recordedSlackRequest) []string {
	paths := make([]string, 0, len(requests))
	for _, request := range requests {
		paths = append(paths, request.path)
	}
	return paths
}

func decodeRecordedStreamChunks(
	t *testing.T,
	request recordedSlackRequest,
) []recordedStreamChunk {
	t.Helper()
	var chunks []recordedStreamChunk
	if err := json.Unmarshal([]byte(request.values.Get("chunks")), &chunks); err != nil {
		t.Fatalf("decode chunks from %s: %v", request.path, err)
	}
	return chunks
}

func TestNativeStreamDeltaRejectsRewrites(t *testing.T) {
	if _, ok := nativeStreamDelta("prefix", "different"); ok {
		t.Fatal("nativeStreamDelta accepted a non-monotonic rewrite")
	}
	if delta, ok := nativeStreamDelta("prefix", "prefix suffix"); !ok || delta != " suffix" {
		t.Fatalf("nativeStreamDelta() = %q, %v; want suffix, true", delta, ok)
	}
}

func TestSplitNativeStreamTextUsesRuneLimit(t *testing.T) {
	input := string(make([]rune, nativeStreamChunkLimit-1)) + "世界"
	chunks := splitNativeStreamText(input)
	if len(chunks) != 2 {
		t.Fatalf("chunk count = %d, want 2", len(chunks))
	}
	if got := len([]rune(chunks[0])); got != nativeStreamChunkLimit {
		t.Errorf("first chunk rune count = %d, want %d", got, nativeStreamChunkLimit)
	}
	if chunks[1] != "界" {
		t.Errorf("second chunk = %q, want 界", chunks[1])
	}
}
