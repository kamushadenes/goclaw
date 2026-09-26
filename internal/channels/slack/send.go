package slack

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nextlevelbuilder/goclaw/internal/channels"
	slackapi "github.com/slack-go/slack"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
)

// Send delivers an outbound message to Slack.
func (c *Channel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return fmt.Errorf("slack bot not running")
	}

	channelID := extractChannelID(msg.ChatID)
	if channelID == "" {
		return fmt.Errorf("empty chat ID for slack send")
	}

	placeholderKey := channelID
	if pk := msg.Metadata["placeholder_key"]; pk != "" {
		placeholderKey = pk
	}
	threadTS := msg.Metadata["message_thread_id"]
	agentThread, hasAgentThread := c.loadAgentThread(placeholderKey)
	if c.agentModeEnabled() && threadTS == "" && hasAgentThread {
		threadTS = agentThread.threadTS
	}

	// Placeholder update (LLM retry notification)
	if msg.Metadata["placeholder_update"] == "true" {
		if c.agentModeEnabled() {
			if hasAgentThread {
				if err := c.setAgentStatus(ctx, agentThread, msg.Content); err != nil {
					slog.Debug("slack assistant status update failed", "error", err)
				}
			}
			return nil
		}
		if pTS, ok := c.placeholders.Load(placeholderKey); ok {
			ts := pTS.(string)
			if _, _, _, err := c.api.UpdateMessageContext(
				ctx,
				channelID,
				ts,
				slackapi.MsgOptionText(msg.Content, false),
			); err != nil {
				slog.Debug("slack placeholder status update failed", "error", err)
			}
		}
		return nil
	}

	content := msg.Content

	// NO_REPLY: remove any persisted/streamed indicator and explicitly clear the
	// native status because no response message will arrive to clear it.
	if content == "" {
		if completed, ok := c.completedStreams.LoadAndDelete(placeholderKey); ok {
			stream := completed.(completedSlackStream)
			if stream.msgTS != "" {
				if _, _, err := c.api.DeleteMessageContext(ctx, stream.channelID, stream.msgTS); err != nil {
					slog.Debug("slack empty native stream delete failed", "error", err)
				}
			}
		}
		if pTS, ok := c.placeholders.Load(placeholderKey); ok {
			c.placeholders.Delete(placeholderKey)
			ts := pTS.(string)
			if _, _, err := c.api.DeleteMessageContext(ctx, channelID, ts); err != nil {
				slog.Debug("slack placeholder delete failed", "error", err)
			}
		}
		if c.agentModeEnabled() && hasAgentThread {
			if err := c.setAgentStatus(ctx, agentThread, ""); err != nil {
				slog.Debug("slack assistant status clear failed", "error", err)
			}
			c.agentThreads.Delete(placeholderKey)
		}
		return nil
	}

	if c.agentModeEnabled() {
		defer c.agentThreads.Delete(placeholderKey)
		if completed, ok := c.completedStreams.LoadAndDelete(placeholderKey); ok {
			stream := completed.(completedSlackStream)
			if !stream.failed && stream.content == content {
				c.sendMediaAttachments(ctx, channelID, threadTS, msg.Media)
				return nil
			}

			// A failed stream, or a final response that differs from the streamed
			// provider text, falls back to one authoritative normal message.
			if stream.msgTS != "" {
				if _, _, err := c.api.DeleteMessageContext(ctx, stream.channelID, stream.msgTS); err != nil {
					slog.Warn("slack native stream fallback delete failed",
						"channel_id", stream.channelID, "error", err)
				}
			}
		}
	}

	content = markdownToSlackMrkdwn(content)

	// Edit placeholder with first chunk, send rest as follow-ups
	if pTS, ok := c.placeholders.Load(placeholderKey); ok {
		c.placeholders.Delete(placeholderKey)
		ts := pTS.(string)

		editContent, remaining := splitAtLimit(content, maxMessageLen)

		opts := []slackapi.MsgOption{slackapi.MsgOptionText(editContent, false)}
		if threadTS != "" {
			opts = append(opts, slackapi.MsgOptionTS(threadTS))
		}

		if _, _, _, editErr := c.api.UpdateMessageContext(ctx, channelID, ts, opts...); editErr == nil {
			if remaining != "" {
				return c.sendChunked(channelID, remaining, threadTS)
			}
			return nil
		} else {
			slog.Warn("slack placeholder edit failed, sending new message",
				"channel_id", channelID, "error", editErr)
		}
	}

	// Handle media attachments
	c.sendMediaAttachments(ctx, channelID, threadTS, msg.Media)

	return c.sendChunked(channelID, content, threadTS)
}

func (c *Channel) sendMediaAttachments(
	_ context.Context,
	channelID, threadTS string,
	mediaItems []bus.MediaAttachment,
) {
	for _, media := range mediaItems {
		if err := c.uploadFile(channelID, threadTS, media); err != nil {
			slog.Warn("slack: file upload failed",
				"file", media.URL, "error", err)
			if sendErr := c.sendChunked(
				channelID,
				fmt.Sprintf("[File upload failed: %s]", media.URL),
				threadTS,
			); sendErr != nil {
				slog.Warn("slack: file upload failure notice failed",
					"channel_id", channelID, "error", sendErr)
			}
		}
	}
}

// sendChunked sends message chunks using markdown-aware splitting.
func (c *Channel) sendChunked(channelID, content, threadTS string) error {
	for _, chunk := range channels.ChunkMarkdown(content, maxMessageLen) {
		opts := []slackapi.MsgOption{slackapi.MsgOptionText(chunk, false)}
		if threadTS != "" {
			opts = append(opts, slackapi.MsgOptionTS(threadTS))
		}

		if _, _, err := c.api.PostMessage(channelID, opts...); err != nil {
			return fmt.Errorf("send slack message: %w", err)
		}
	}
	return nil
}

// splitAtLimit splits content into first chunk + remaining using markdown-aware chunking.
func splitAtLimit(content string, maxLen int) (chunk, remaining string) {
	chunks := channels.ChunkMarkdown(content, maxLen)
	if len(chunks) == 0 {
		return "", ""
	}
	if len(chunks) == 1 {
		return chunks[0], ""
	}
	return chunks[0], strings.Join(chunks[1:], "\n")
}
