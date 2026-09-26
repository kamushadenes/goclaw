package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	slackapi "github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"

	"github.com/nextlevelbuilder/goclaw/internal/channels"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

const appContextChangedEventType = slackevents.EventsAPIType("app_context_changed")

// slack-go v0.27 predates app_context_changed and does not retain the context
// field added to app_home_opened. Register local event shapes before any Socket
// Mode clients start parsing events.
func init() {
	slackevents.EventsAPIInnerEventMapping[appContextChangedEventType] = appContextChangedEvent{}
	slackevents.EventsAPIInnerEventMapping[slackevents.AppHomeOpened] = appHomeOpenedEvent{}
}

type slackAppContext struct {
	Entities []json.RawMessage `json:"entities,omitempty"`
}

type appContextChangedEvent struct {
	Type           string          `json:"type"`
	User           string          `json:"user,omitempty"`
	Context        slackAppContext `json:"context"`
	EventTimestamp string          `json:"event_ts"`
}

type appHomeOpenedEvent struct {
	Type           string          `json:"type"`
	User           string          `json:"user"`
	Channel        string          `json:"channel"`
	Tab            string          `json:"tab"`
	Context        slackAppContext `json:"context"`
	EventTimestamp string          `json:"event_ts"`
}

type agentContextState struct {
	containerChannelID string
	threadTS           string
	context            json.RawMessage
	updatedAt          time.Time
}

type slackEventEnvelope struct {
	Authorizations []struct {
		UserID string `json:"user_id"`
		IsBot  bool   `json:"is_bot"`
	} `json:"authorizations"`
	AuthedUsers []string `json:"authed_users"`
	Event       struct {
		AppContext *slackAppContext `json:"app_context,omitempty"`
	} `json:"event"`
}

func (c *Channel) handleEventsAPI(evt socketmode.Event) {
	eventsAPI, ok := evt.Data.(slackevents.EventsAPIEvent)
	if !ok {
		return
	}

	// Ack immediately (Slack requires ack within ~3s)
	c.sm.Ack(*evt.Request)

	switch ev := eventsAPI.InnerEvent.Data.(type) {
	case *slackevents.MessageEvent:
		if evt.Request != nil {
			c.captureMessageAppContext(ev.User, evt.Request.Payload)
		}
		c.handleMessage(ev)
	case *slackevents.AppMentionEvent:
		c.handleAppMention(ev)
	case *slackevents.AssistantThreadStartedEvent:
		c.trackAssistantThread(ev.AssistantThread, "assistant_thread_started")
	case *slackevents.AssistantThreadContextChangedEvent:
		c.trackAssistantThread(ev.AssistantThread, "assistant_thread_context_changed")
	case *appHomeOpenedEvent:
		c.trackAppHomeOpened(ev)
	case *appContextChangedEvent:
		var payload json.RawMessage
		if evt.Request != nil {
			payload = evt.Request.Payload
		}
		c.trackAppContextChanged(ev, payload)
	}
}

func (c *Channel) trackAssistantThread(thread slackevents.AssistantThread, eventType string) {
	if !c.agentModeEnabled() || thread.UserID == "" {
		return
	}

	state := agentContextState{
		containerChannelID: thread.ChannelID,
		threadTS:           thread.ThreadTimeStamp,
		updatedAt:          time.Now(),
	}
	if thread.Context.ChannelID != "" ||
		thread.Context.TeamID != "" ||
		thread.Context.EnterpriseID != "" {
		state.context = encodeAgentContext(thread.Context)
	}
	c.agentContexts.Store(thread.UserID, state)
	slog.Debug("slack agent container context tracked",
		"event", eventType, "user_id", thread.UserID,
		"channel_id", thread.ChannelID, "thread_ts", thread.ThreadTimeStamp)
}

func (c *Channel) trackAppHomeOpened(ev *appHomeOpenedEvent) {
	if !c.agentModeEnabled() || ev == nil || ev.Tab != "messages" || ev.User == "" {
		return
	}

	state, _ := c.loadAgentContext(ev.User)
	state.containerChannelID = ev.Channel
	if len(ev.Context.Entities) > 0 {
		state.context = encodeAgentContext(ev.Context)
	}
	state.updatedAt = time.Now()
	c.agentContexts.Store(ev.User, state)
	slog.Debug("slack agent container opened",
		"user_id", ev.User, "channel_id", ev.Channel, "tab", ev.Tab)
}

func (c *Channel) trackAppContextChanged(ev *appContextChangedEvent, payload json.RawMessage) {
	if !c.agentModeEnabled() || ev == nil {
		return
	}

	userID := ev.User
	if userID == "" {
		userID = authorizedEventUser(payload, c.botUserID)
	}
	if userID == "" {
		slog.Debug("slack app context ignored: viewer user ID unavailable")
		return
	}

	state, _ := c.loadAgentContext(userID)
	state.context = encodeAppContext(ev.Context)
	state.updatedAt = time.Now()
	c.agentContexts.Store(userID, state)
	slog.Debug("slack app context tracked",
		"user_id", userID, "entities", len(ev.Context.Entities))
}

func (c *Channel) captureMessageAppContext(userID string, payload json.RawMessage) {
	if !c.agentModeEnabled() || userID == "" || len(payload) == 0 {
		return
	}

	var envelope slackEventEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Event.AppContext == nil {
		return
	}
	state, _ := c.loadAgentContext(userID)
	state.context = encodeAppContext(*envelope.Event.AppContext)
	state.updatedAt = time.Now()
	c.agentContexts.Store(userID, state)
}

func encodeAppContext(appContext slackAppContext) json.RawMessage {
	if len(appContext.Entities) == 0 {
		return nil
	}
	return encodeAgentContext(appContext)
}

func encodeAgentContext(value any) json.RawMessage {
	contextJSON, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return contextJSON
}

func authorizedEventUser(payload json.RawMessage, botUserID string) string {
	if len(payload) == 0 {
		return ""
	}
	var envelope slackEventEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	for _, authorization := range envelope.Authorizations {
		if authorization.UserID != "" && !authorization.IsBot && authorization.UserID != botUserID {
			return authorization.UserID
		}
	}
	for _, userID := range envelope.AuthedUsers {
		if userID != "" && userID != botUserID {
			return userID
		}
	}
	return ""
}

func (c *Channel) loadAgentContext(userID string) (agentContextState, bool) {
	value, ok := c.agentContexts.Load(userID)
	if !ok {
		return agentContextState{}, false
	}
	state, ok := value.(agentContextState)
	return state, ok
}

func (c *Channel) agentThreadTS(userID, channelID, eventThreadTS, eventTS string) string {
	if eventThreadTS != "" {
		return eventThreadTS
	}
	if state, ok := c.loadAgentContext(userID); ok &&
		state.containerChannelID == channelID &&
		state.threadTS != "" {
		return state.threadTS
	}
	return eventTS
}

func (c *Channel) agentContextMetadata(userID string) string {
	state, ok := c.loadAgentContext(userID)
	if !ok || len(state.context) == 0 || !json.Valid(state.context) {
		return ""
	}
	return string(state.context)
}

func (c *Channel) handleMessage(ev *slackevents.MessageEvent) {
	ctx := context.Background()
	ctx = store.WithTenantID(ctx, c.TenantID())
	// For message_changed: extract user/text from the nested Message field.
	// Only process if the edit introduces a new @bot mention.
	if ev.SubType == "message_changed" {
		if ev.Message == nil {
			return
		}
		// Skip bot's own edits or messages without a user
		if ev.Message.User == c.botUserID || ev.Message.User == "" {
			return
		}
		// Only process if the edited message mentions the bot
		if !c.isBotMentioned(ev.Message.Text) {
			return
		}
		// Check that the previous version did NOT mention the bot (newly added mention)
		if ev.PreviousMessage != nil && c.isBotMentioned(ev.PreviousMessage.Text) {
			return
		}
		// Promote nested fields to top-level for unified processing below
		ev.User = ev.Message.User
		ev.Text = ev.Message.Text
		ev.TimeStamp = ev.Message.Timestamp
		ev.ThreadTimeStamp = ev.Message.ThreadTimestamp
	}

	if ev.User == c.botUserID || ev.User == "" {
		return
	}

	// Skip message subtypes (edits, deletes, bot_message, joins, etc.)
	// Allow "file_share" and "message_changed" subtypes.
	if ev.SubType != "" && ev.SubType != "file_share" && ev.SubType != "message_changed" {
		return
	}

	// Explicit dedup: prevent duplicate processing on Socket Mode reconnect
	dedupKey := ev.Channel + ":" + ev.TimeStamp
	if _, loaded := c.dedup.LoadOrStore(dedupKey, time.Now()); loaded {
		return
	}

	senderID := ev.User
	channelID := ev.Channel
	content := ev.Text

	isDM := ev.ChannelType == "im"
	peerKind := "group"
	if isDM {
		peerKind = "direct"
	}

	displayName := c.resolveDisplayName(senderID)

	// Policy check
	if isDM {
		if !c.checkDMPolicy(ctx, senderID, channelID) {
			return
		}
	} else {
		if !c.checkGroupPolicy(ctx, senderID, channelID) {
			return
		}
	}

	// Process file attachments from Slack message
	var mediaPaths []string
	var allItems []mediaItem
	if ev.Message != nil && len(ev.Message.Files) > 0 {
		items, docContent := c.resolveMedia(ev.Message.Files)
		allItems = append(allItems, items...)

		if docContent != "" {
			if content != "" {
				content = content + "\n\n" + docContent
			} else {
				content = docContent
			}
		}
	}

	// Fetch reply context + media from thread parent message.
	// Only when replying in a thread (ThreadTimeStamp != TimeStamp).
	threadTS := ev.ThreadTimeStamp
	if threadTS != "" && threadTS != ev.TimeStamp {
		replyCtx, replyItems := c.fetchThreadParentContext(context.Background(), channelID, threadTS)
		if replyCtx != "" {
			if content != "" {
				content = replyCtx + "\n\n" + content
			} else {
				content = replyCtx
			}
		}
		// Reply media first (context), current media second.
		if len(replyItems) > 0 {
			allItems = append(replyItems, allItems...)
		}
	}

	// Build media tags and collect file paths from all items.
	if len(allItems) > 0 {
		mediaTags := buildMediaTags(allItems)
		if mediaTags != "" {
			if content != "" {
				content = mediaTags + "\n\n" + content
			} else {
				content = mediaTags
			}
		}
		for _, item := range allItems {
			if item.FilePath != "" {
				mediaPaths = append(mediaPaths, item.FilePath)
			}
		}
	}

	if content == "" {
		return
	}

	// Determine local_key and thread context
	localKey := channelID
	if threadTS != "" {
		localKey = fmt.Sprintf("%s:thread:%s", channelID, threadTS)
	}
	historyKey := localKey

	// Mention gating in groups (with thread participation cache)
	if !isDM && c.RequireMention() {
		mentioned := c.isBotMentioned(content)

		// Thread participation cache: auto-reply in threads where bot previously participated
		if !mentioned && threadTS != "" && c.threadTTL > 0 {
			participKey := channelID + ":particip:" + threadTS
			if lastReply, ok := c.threadParticip.Load(participKey); ok {
				if time.Since(lastReply.(time.Time)) < c.threadTTL {
					mentioned = true
					slog.Debug("slack: auto-reply in participated thread",
						"channel_id", channelID, "thread_ts", threadTS)
				} else {
					c.threadParticip.Delete(participKey)
				}
			}
		}

		if !mentioned {
			c.GroupHistory().Record(historyKey, channels.HistoryEntry{
				Sender:    displayName,
				SenderID:  senderID,
				Body:      content,
				Media:     mediaPaths,
				Timestamp: time.Now(),
				MessageID: ev.TimeStamp,
			}, c.HistoryLimit())

			// Collect contact even when bot is not mentioned (cache prevents DB spam).
			if cc := c.ContactCollector(); cc != nil {
				cc.EnsureContact(ctx, c.Type(), c.Name(), senderID, senderID, displayName, "", "group", "user", "", "")
			}

			slog.Debug("slack group message recorded (no mention)",
				"channel_id", channelID, "user", displayName)
			return
		}
	}

	content = c.stripBotMention(content)
	content = strings.TrimSpace(content)

	slog.Debug("slack message received",
		"sender_id", senderID, "channel_id", channelID,
		"is_dm", isDM, "preview", channels.Truncate(content, 50))

	replyThreadTS := threadTS
	if c.agentModeEnabled() {
		replyThreadTS = c.agentThreadTS(senderID, channelID, threadTS, ev.TimeStamp)
		if replyThreadTS != "" {
			localKey = fmt.Sprintf("%s:thread:%s", channelID, replyThreadTS)
		}
	} else if !isDM && replyThreadTS == "" {
		replyThreadTS = ev.TimeStamp // start thread from the triggering message
	}
	c.startResponseIndicator(ctx, channelID, localKey, replyThreadTS, senderID, !isDM)

	// Build final content with group history context
	finalContent := content
	if peerKind == "group" {
		annotated := fmt.Sprintf("[From: %s]\n%s", displayName, content)
		if c.HistoryLimit() > 0 {
			// Collect media from pending history (files downloaded by earlier non-mentioned messages).
			if histMediaPaths := c.GroupHistory().CollectMedia(historyKey); len(histMediaPaths) > 0 {
				mediaPaths = append(mediaPaths, histMediaPaths...)
			}
			finalContent = c.GroupHistory().BuildContext(historyKey, annotated, c.HistoryLimit())
		} else {
			finalContent = annotated
		}
	}

	metadata := map[string]string{
		"message_id":      ev.TimeStamp,
		"user_id":         senderID,
		"username":        displayName,
		"display_name":    channels.SanitizeDisplayName(displayName),
		"channel_id":      channelID,
		"is_dm":           fmt.Sprintf("%t", isDM),
		"local_key":       localKey,
		"placeholder_key": localKey,
	}
	if replyThreadTS != "" {
		metadata["message_thread_id"] = replyThreadTS
	}
	if appContext := c.agentContextMetadata(senderID); appContext != "" {
		metadata["slack_app_context"] = appContext
	}

	// Message debounce: batch rapid messages per-thread
	if c.debounceDelay > 0 {
		if c.debounceMessage(localKey, senderID, channelID, finalContent, mediaPaths, metadata, peerKind, true) {
			// Record thread participation even when debounced
			if peerKind == "group" && replyThreadTS != "" {
				participKey := channelID + ":particip:" + replyThreadTS
				c.threadParticip.Store(participKey, time.Now())
			}
			return
		}
	}

	c.HandleAuthorizedMessage(senderID, channelID, finalContent, mediaPaths, metadata, peerKind)

	// Record thread participation for auto-reply cache
	if peerKind == "group" {
		if replyThreadTS != "" {
			participKey := channelID + ":particip:" + replyThreadTS
			c.threadParticip.Store(participKey, time.Now())
		}
		c.GroupHistory().Clear(historyKey)
	}
}

// fetchThreadParentContext fetches the thread-start message and returns a formatted
// reply context string + any downloaded media from the parent message.
func (c *Channel) fetchThreadParentContext(ctx context.Context, channelID, threadTS string) (string, []mediaItem) {
	params := &slackapi.GetConversationHistoryParameters{
		ChannelID: channelID,
		Latest:    threadTS,
		Limit:     1,
		Inclusive: true,
	}
	history, err := c.api.GetConversationHistoryContext(ctx, params)
	if err != nil || len(history.Messages) == 0 {
		slog.Debug("slack: failed to fetch thread parent", "channel", channelID, "thread_ts", threadTS, "error", err)
		return "", nil
	}

	parent := &history.Messages[0]

	// Build reply context text.
	var replyCtx string
	if parent.Text != "" {
		body := channels.Truncate(parent.Text, 500)
		userName := c.resolveDisplayName(parent.User)
		replyCtx = fmt.Sprintf("[Replying to %s]\n%s\n[/Replying]", userName, body)
	}

	// Download files from parent message.
	var replyItems []mediaItem
	if len(parent.Files) > 0 {
		items, docContent := c.resolveMedia(parent.Files)
		for i := range items {
			items[i].FromReply = true
		}
		replyItems = items
		// Append extracted document text to reply context.
		if docContent != "" {
			if replyCtx != "" {
				replyCtx += "\n\n" + docContent
			} else {
				replyCtx = docContent
			}
		}
	}

	return replyCtx, replyItems
}
