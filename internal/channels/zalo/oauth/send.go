package zalooauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

// sendMessagePath is the OA customer-service message endpoint.
const sendMessagePath = "/v3.0/oa/message/cs"

// SendText delivers a plain text message to userID. Returns the upstream
// message_id on success.
func (c *Channel) SendText(ctx context.Context, userID, text string) (string, error) {
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message":   map[string]any{"text": text},
	}
	mid, err := c.post(ctx, sendMessagePath, body)
	if err == nil {
		slog.Info("zalo_oauth.sent", "type", "text", "message_id", mid, "oa_id", c.creds.OAID)
	}
	return mid, err
}

// SendImage uploads an image and posts an attachment message. mime is the
// MIME type (e.g. "image/png") — used by some implementations of upload
// validation; Zalo's OA SDK accepts the bytes directly so we don't pass it
// to the upload endpoint.
func (c *Channel) SendImage(ctx context.Context, userID string, data []byte, _ string) (string, error) {
	tok, err := c.uploadImage(ctx, data)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message": map[string]any{
			"attachment": map[string]any{
				"type":    "image",
				"payload": map[string]any{"token": tok},
			},
		},
	}
	mid, err := c.post(ctx, sendMessagePath, body)
	if err == nil {
		slog.Info("zalo_oauth.sent", "type", "image", "message_id", mid, "oa_id", c.creds.OAID)
	}
	return mid, err
}

// SendFile uploads a file and posts an attachment message. filename is
// passed in the multipart "filename" field so Zalo preserves it for the
// recipient.
func (c *Channel) SendFile(ctx context.Context, userID string, data []byte, filename, _ string) (string, error) {
	tok, err := c.uploadFile(ctx, data, filename)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message": map[string]any{
			"attachment": map[string]any{
				"type":    "file",
				"payload": map[string]any{"token": tok},
			},
		},
	}
	mid, err := c.post(ctx, sendMessagePath, body)
	if err == nil {
		slog.Info("zalo_oauth.sent", "type", "file", "message_id", mid, "oa_id", c.creds.OAID)
	}
	return mid, err
}

// post wraps the API call with a retry-once-on-auth-error pattern. The first
// auth-classified error triggers ForceRefresh and one retry; a second auth
// error fails cleanly (no infinite loop). Non-auth errors return immediately.
//
// Loop is structured so EVERY iteration ends in either a success-return,
// a non-auth-error-return, or (only on attempt 0) a continue. The 2nd
// iteration cannot loop further — it returns unconditionally.
func (c *Channel) post(ctx context.Context, path string, body any) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.tokens.Access(ctx)
		if err != nil {
			return "", err
		}
		raw, err := c.client.apiPost(ctx, path, body, tok)
		if err == nil {
			return parseMessageResponse(raw)
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.isAuth() && attempt == 0 {
			c.tokens.ForceRefresh()
			continue
		}
		return "", err
	}
	// Unreachable — second iteration always returns. Defensive panic so a
	// future refactor that violates the loop invariant fails loudly.
	panic("zalo_oauth.post: loop exited without returning (broken invariant)")
}

// parseMessageResponse extracts message_id from the standard envelope:
// {"error":0,"data":{"message_id":"...","recipient_id":"..."}}
func parseMessageResponse(raw json.RawMessage) (string, error) {
	var env struct {
		Data struct {
			MessageID string `json:"message_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("zalo_oauth: decode message response: %w", err)
	}
	return env.Data.MessageID, nil
}
