package slack

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	slackapi "github.com/slack-go/slack"

	"github.com/nextlevelbuilder/goclaw/internal/channels"
)

const (
	streamThrottleInterval = 1000 * time.Millisecond
	nativeStreamChunkLimit = 12_000
	agentStateTTL          = 10 * time.Minute
	agentContextTTL        = 24 * time.Hour
	completedStreamTTL     = 5 * time.Minute
)

// agentThreadState contains the per-thread routing Slack's Agent APIs need.
// It is keyed by localKey so concurrent agent threads do not share recipients.
type agentThreadState struct {
	channelID       string
	threadTS        string
	recipientUserID string
	recipientTeamID string
	isGroup         bool
	updatedAt       time.Time
}

// completedSlackStream bridges the event stream to the final outbound Send call.
// A successful native stream already delivered the text, so Send only needs to
// upload media. A failed or divergent stream is deleted and sent through the
// normal chat.postMessage fallback.
type completedSlackStream struct {
	channelID   string
	msgTS       string
	content     string
	failed      bool
	completedAt time.Time
}

// slackStream implements channels.ChannelStream for Slack. Legacy streams edit
// the "Thinking..." placeholder with chat.update. Agent-mode streams append
// deltas with chat.appendStream and close with chat.stopStream.
type slackStream struct {
	api       *slackapi.Client
	channelID string
	threadTS  string
	msgTS     string
	native    bool

	lastUpdate time.Time
	latestText string
	sentText   string
	stopped    bool
	failed     bool
	streamErr  error
	mu         sync.Mutex
}

// Update sends the latest accumulated text. Agent-mode updates calculate the
// unsent suffix because ChannelStream.Update receives the full response so far,
// while Slack's native API only accepts append-only deltas.
func (s *slackStream) Update(ctx context.Context, fullText string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.native {
		s.updateNativeLocked(ctx, fullText)
		return
	}

	if time.Since(s.lastUpdate) < streamThrottleInterval || s.msgTS == "" {
		return
	}

	formatted := markdownToSlackMrkdwn(fullText)
	if len(formatted) > maxMessageLen {
		formatted = formatted[:maxMessageLen] + "..."
	}

	opts := []slackapi.MsgOption{slackapi.MsgOptionText(formatted, false)}
	_, _, _, err := s.api.UpdateMessageContext(ctx, s.channelID, s.msgTS, opts...)
	if err != nil {
		slog.Debug("slack stream chunk update failed", "error", err)
		return
	}

	s.lastUpdate = time.Now()
}

func (s *slackStream) updateNativeLocked(ctx context.Context, fullText string) {
	if s.stopped || s.failed || s.msgTS == "" {
		return
	}

	s.latestText = fullText
	if time.Since(s.lastUpdate) < streamThrottleInterval {
		return
	}

	delta, ok := nativeStreamDelta(s.sentText, fullText)
	if !ok {
		s.failLocked(fmt.Errorf("slack native stream text changed non-monotonically"))
		return
	}
	if delta == "" {
		return
	}

	if err := s.appendNativeLocked(ctx, delta); err != nil {
		s.failLocked(err)
		return
	}
	s.sentText = fullText
	s.lastUpdate = time.Now()
}

func (s *slackStream) appendNativeLocked(ctx context.Context, delta string) error {
	if _, _, err := s.api.AppendStreamContext(
		ctx,
		s.channelID,
		s.msgTS,
		slackapi.MsgOptionChunks(markdownStreamChunks(delta)...),
	); err != nil {
		return fmt.Errorf("slack chat.appendStream: %w", err)
	}
	return nil
}

// Stop flushes any throttled suffix as the final chat.stopStream chunk. It is
// idempotent because the channel manager calls Stop before FinalizeStream and
// also calls it for intermediate tool/reasoning stream transitions.
func (s *slackStream) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.native {
		return nil
	}
	return s.stopNativeLocked(ctx)
}

func (s *slackStream) stopNativeLocked(ctx context.Context) error {
	if s.stopped {
		return s.streamErr
	}
	s.stopped = true

	if s.msgTS == "" {
		s.failLocked(fmt.Errorf("slack native stream has no message timestamp"))
		return s.streamErr
	}

	var finalChunks []slackapi.StreamChunk
	if !s.failed {
		delta, ok := nativeStreamDelta(s.sentText, s.latestText)
		if !ok {
			s.failLocked(fmt.Errorf("slack native stream text changed non-monotonically"))
		} else if delta != "" {
			finalChunks = markdownStreamChunks(delta)
		}
	}

	if _, _, err := s.api.StopStreamContext(
		ctx,
		s.channelID,
		s.msgTS,
		slackapi.MsgOptionChunks(finalChunks...),
	); err != nil {
		s.failLocked(fmt.Errorf("slack chat.stopStream: %w", err))
	} else if len(finalChunks) > 0 {
		s.sentText = s.latestText
	}

	return s.streamErr
}

func (s *slackStream) failLocked(err error) {
	if err == nil {
		return
	}
	s.failed = true
	if s.streamErr == nil {
		s.streamErr = err
	}
	slog.Debug("slack native stream failed", "error", err)
}

// MessageID returns 0 — Slack uses string timestamps, not integer IDs.
func (s *slackStream) MessageID() int {
	return 0
}

// MsgTS returns the Slack message timestamp for final delivery handoff.
func (s *slackStream) MsgTS() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgTS
}

func (s *slackStream) completion() completedSlackStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return completedSlackStream{
		channelID:   s.channelID,
		msgTS:       s.msgTS,
		content:     s.sentText,
		failed:      s.failed,
		completedAt: time.Now(),
	}
}

func nativeStreamDelta(sentText, fullText string) (string, bool) {
	if !strings.HasPrefix(fullText, sentText) {
		return "", false
	}
	return fullText[len(sentText):], true
}

func splitNativeStreamText(text string) []string {
	if text == "" {
		return nil
	}
	runes := []rune(text)
	chunks := make([]string, 0, (len(runes)+nativeStreamChunkLimit-1)/nativeStreamChunkLimit)
	for len(runes) > 0 {
		n := min(len(runes), nativeStreamChunkLimit)
		chunks = append(chunks, string(runes[:n]))
		runes = runes[n:]
	}
	return chunks
}

func (c *Channel) agentModeEnabled() bool {
	return c.config.AgentMode != nil && *c.config.AgentMode
}

// StreamEnabled reports whether streaming is active for DMs or groups. Agent
// mode always streams because chat.startStream is its response transport.
func (c *Channel) StreamEnabled(isGroup bool) bool {
	if c.agentModeEnabled() {
		return true
	}
	if isGroup {
		return c.config.GroupStream != nil && *c.config.GroupStream
	}
	return c.config.DMStream != nil && *c.config.DMStream
}

// startResponseIndicator starts either Slack's native Assistant status or the
// legacy persisted "Thinking..." placeholder.
func (c *Channel) startResponseIndicator(
	ctx context.Context,
	channelID, localKey, threadTS, recipientUserID string,
	isGroup bool,
) {
	if !c.agentModeEnabled() {
		opts := []slackapi.MsgOption{slackapi.MsgOptionText("Thinking...", false)}
		if threadTS != "" {
			opts = append(opts, slackapi.MsgOptionTS(threadTS))
		}
		if _, placeholderTS, err := c.api.PostMessageContext(ctx, channelID, opts...); err == nil {
			c.placeholders.Store(localKey, placeholderTS)
		}
		return
	}

	state := agentThreadState{
		channelID:       channelID,
		threadTS:        threadTS,
		recipientUserID: recipientUserID,
		recipientTeamID: c.teamID,
		isGroup:         isGroup,
		updatedAt:       time.Now(),
	}
	c.agentThreads.Store(localKey, state)
	if err := c.setAgentStatus(ctx, state, "Thinking..."); err != nil {
		slog.Debug("slack assistant status failed",
			"channel_id", channelID, "thread_ts", threadTS, "error", err)
	}
}

func (c *Channel) setAgentStatus(ctx context.Context, state agentThreadState, status string) error {
	if state.channelID == "" || state.threadTS == "" {
		return fmt.Errorf("slack assistant status requires channel_id and thread_ts")
	}
	return c.api.SetAssistantThreadsStatusContext(ctx, slackapi.AssistantThreadsSetStatusParameters{
		ChannelID: state.channelID,
		ThreadTS:  state.threadTS,
		Status:    status,
	})
}

// CreateStream creates a per-run streaming handle for the given local key.
// Agent mode starts a native Slack stream; legacy mode reuses the placeholder
// that handleMessage or handleAppMention already posted.
func (c *Channel) CreateStream(ctx context.Context, chatID string, _ bool) (channels.ChannelStream, error) {
	if !c.agentModeEnabled() {
		pTS, pOK := c.placeholders.Load(chatID)
		if !pOK {
			return &slackStream{
				api:       c.api,
				channelID: extractChannelID(chatID),
				threadTS:  extractThreadTS(chatID),
			}, nil
		}

		return &slackStream{
			api:       c.api,
			channelID: extractChannelID(chatID),
			threadTS:  extractThreadTS(chatID),
			msgTS:     pTS.(string),
		}, nil
	}

	state, ok := c.loadAgentThread(chatID)
	if !ok {
		state = agentThreadState{
			channelID: extractChannelID(chatID),
			threadTS:  extractThreadTS(chatID),
			updatedAt: time.Now(),
		}
	}
	if state.channelID == "" || state.threadTS == "" {
		return nil, fmt.Errorf("slack chat.startStream requires channel and thread timestamp")
	}

	opts := []slackapi.MsgOption{
		slackapi.MsgOptionTS(state.threadTS),
		slackapi.MsgOptionChunks(),
	}
	if state.isGroup {
		if state.recipientUserID != "" {
			opts = append(opts, slackapi.MsgOptionRecipientUserID(state.recipientUserID))
		}
		if state.recipientTeamID != "" {
			opts = append(opts, slackapi.MsgOptionRecipientTeamID(state.recipientTeamID))
		}
	}

	responseChannel, msgTS, err := c.api.StartStreamContext(ctx, state.channelID, opts...)
	if err != nil {
		return nil, fmt.Errorf("slack chat.startStream: %w", err)
	}
	if responseChannel != "" {
		state.channelID = responseChannel
	}
	if msgTS == "" {
		return nil, fmt.Errorf("slack chat.startStream returned an empty message timestamp")
	}

	return &slackStream{
		api:       c.api,
		channelID: state.channelID,
		threadTS:  state.threadTS,
		msgTS:     msgTS,
		native:    true,
	}, nil
}

func markdownStreamChunks(text string) []slackapi.StreamChunk {
	textChunks := splitNativeStreamText(text)
	chunks := make([]slackapi.StreamChunk, 0, len(textChunks))
	for _, chunk := range textChunks {
		chunks = append(chunks, slackapi.NewMarkdownTextChunk(chunk))
	}
	return chunks
}

func (c *Channel) loadAgentThread(localKey string) (agentThreadState, bool) {
	value, ok := c.agentThreads.Load(localKey)
	if !ok {
		return agentThreadState{}, false
	}
	state, ok := value.(agentThreadState)
	return state, ok
}

// ReasoningStreamEnabled returns false — Slack presents one native response
// stream at a time rather than separate reasoning and answer lanes.
func (c *Channel) ReasoningStreamEnabled() bool { return false }

// FinalizeStream records the native stream completion so Send does not duplicate
// it. stopNativeLocked is idempotent because the manager calls Stop first.
func (c *Channel) FinalizeStream(ctx context.Context, chatID string, stream channels.ChannelStream) {
	ss, ok := stream.(*slackStream)
	if !ok || ss.msgTS == "" {
		return
	}
	if ss.native {
		_ = ss.Stop(ctx)
		c.completedStreams.Store(chatID, ss.completion())
		return
	}
	c.placeholders.Store(chatID, ss.MsgTS())
}

// extractChannelID gets the channel ID from a local_key.
func extractChannelID(localKey string) string {
	if idx := strings.Index(localKey, ":thread:"); idx > 0 {
		return localKey[:idx]
	}
	return localKey
}

// extractThreadTS gets the thread_ts from a local_key, or "" if not threaded.
func extractThreadTS(localKey string) string {
	const prefix = ":thread:"
	if idx := strings.Index(localKey, prefix); idx > 0 {
		return localKey[idx+len(prefix):]
	}
	return ""
}
