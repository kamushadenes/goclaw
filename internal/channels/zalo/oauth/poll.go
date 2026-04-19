package zalooauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/channels"
)

// thread is a single entry in /v3.0/oa/listrecentchat. Field names per
// ChickenAI SDK + research §4 (UNVERIFIED — first prod run should dump
// raw JSON to confirm).
type thread struct {
	UserID          string `json:"user_id"`
	LastMessageTime int64  `json:"last_message_time"` // unix ms
	LastMessage     string `json:"last_message,omitempty"`
}

// message is a single entry from /v3.0/oa/conversation.
type message struct {
	MessageID string `json:"message_id"`
	UserID    string `json:"user_id"`
	FromID    string `json:"from_id"`
	Time      int64  `json:"time"`
	Text      string `json:"text,omitempty"`
	Type      string `json:"type,omitempty"` // text/image/file/sticker
}

// listRecentChat fetches the most-recent threads. Bounded by `count`.
// Zalo OA v2.0 legacy read endpoints encode GET params as a single JSON
// blob in the `data` query parameter (e.g. ?data={"offset":0,"count":10}).
func (c *Channel) listRecentChat(ctx context.Context, offset, count int) ([]thread, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]int{"offset": offset, "count": count})
	if err != nil {
		return nil, fmt.Errorf("zalo_oauth: marshal listrecentchat params: %w", err)
	}
	q := url.Values{"data": {string(data)}}
	raw, err := c.client.apiGet(ctx, "/v2.0/oa/getlistrecentchat", q, tok)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Data []thread `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, fmt.Errorf("zalo_oauth: decode listrecentchat: %w", err)
	}
	return wrap.Data, nil
}

// getConversation fetches recent messages for a single thread.
func (c *Channel) getConversation(ctx context.Context, userID string, offset, count int) ([]message, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]any{"user_id": userID, "offset": offset, "count": count})
	if err != nil {
		return nil, fmt.Errorf("zalo_oauth: marshal getconversation params: %w", err)
	}
	q := url.Values{"data": {string(data)}}
	raw, err := c.client.apiGet(ctx, "/v2.0/oa/getconversation", q, tok)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Data []message `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, fmt.Errorf("zalo_oauth: decode conversation: %w", err)
	}
	return wrap.Data, nil
}

// pollOnce runs one polling cycle. Returns ErrRateLimit if Zalo signals
// 429 (caller should back off); other errors are transient and the next
// cycle retries normally.
//
// v1 limitation: the listrecentchat endpoint returns a window of recent
// threads. High-volume OAs can rotate threads off the window between
// polls, missing messages on those rotated-out threads. Webhook upgrade
// (v2) is the structural fix.
func (c *Channel) pollOnce(ctx context.Context) error {
	if c.skipPollIfAuthFailed() {
		return nil
	}

	threads, err := c.listRecentChat(ctx, 0, listRecentChatCount)
	if err != nil {
		return err
	}

	// Process newest-first so the top-K cap keeps the freshest threads.
	sort.SliceStable(threads, func(i, j int) bool {
		return threads[i].LastMessageTime > threads[j].LastMessageTime
	})

	processed := 0
	for _, t := range threads {
		if processed >= c.topKThreads {
			slog.Debug("zalo_oauth.poll.fanout_capped",
				"oa_id", c.creds.OAID, "top_k", c.topKThreads, "total_threads", len(threads))
			break
		}
		if t.UserID == "" {
			continue
		}
		if t.LastMessageTime <= c.cursor.Get(t.UserID) {
			continue // no new activity since last seen
		}
		if err := c.pollThread(ctx, t.UserID); err != nil {
			if errors.Is(err, ErrRateLimit) {
				return err // bubble immediately, stop the cycle
			}
			slog.Warn("zalo_oauth.poll.thread_failed",
				"oa_id", c.creds.OAID, "user_id", t.UserID, "error", err)
			continue
		}
		processed++
	}
	return nil
}

// pollThread fetches one user's recent messages, filters out OA echoes +
// already-seen messages, and publishes new ones via BaseChannel.HandleMessage.
func (c *Channel) pollThread(ctx context.Context, userID string) error {
	msgs, err := c.getConversation(ctx, userID, 0, conversationCount)
	if err != nil {
		return err
	}
	// Process oldest-first so the cursor advances monotonically.
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].Time < msgs[j].Time })

	seenAt := c.cursor.Get(userID)
	for _, m := range msgs {
		if m.FromID == c.creds.OAID {
			continue // our own echo
		}
		if m.Time <= seenAt {
			continue
		}
		c.dispatchInbound(m, userID)
		c.cursor.Advance(userID, m.Time)
		seenAt = m.Time
	}
	return nil
}

// dispatchInbound maps a Zalo message into a BaseChannel.HandleMessage call.
// Phase 04 emits text only — non-text payloads are logged and skipped.
func (c *Channel) dispatchInbound(m message, chatID string) {
	if m.Type != "" && m.Type != "text" {
		slog.Info("zalo_oauth.poll.non_text_skipped",
			"oa_id", c.creds.OAID, "user_id", chatID, "message_id", m.MessageID, "type", m.Type)
		return
	}
	if m.Text == "" {
		return
	}
	metadata := map[string]string{
		"message_id": m.MessageID,
		"platform":   "zalo_oauth",
	}
	c.BaseChannel.HandleMessage(m.FromID, chatID, m.Text, nil, metadata, "direct")
}

// skipPollIfAuthFailed mirrors safety-ticker's skip behavior: once health
// is Failed/Auth, we stop calling the API until the operator re-auths.
func (c *Channel) skipPollIfAuthFailed() bool {
	snap := c.HealthSnapshot()
	return snap.State == channels.ChannelHealthStateFailed && snap.FailureKind == channels.ChannelFailureKindAuth
}

const (
	listRecentChatCount = 10
	conversationCount   = 20
	defaultTopKThreads  = 20
	defaultPollInterval = 15 * time.Second
	rateLimitBackoff    = 30 * time.Second
	cursorFlushInterval = 60 * time.Second
)

// pollIntervalFromCfg clamps cfg.PollIntervalSeconds to the safe range.
func pollIntervalFromCfg(s int) time.Duration {
	switch {
	case s < 5:
		return defaultPollInterval
	case s > 120:
		return 120 * time.Second
	default:
		return time.Duration(s) * time.Second
	}
}
