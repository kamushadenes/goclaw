package zalooauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nextlevelbuilder/goclaw/internal/config"
)

// isZaloSupportedFileMIME reports whether mime is one of the document
// formats Zalo's /v2.0/oa/upload/file endpoint accepts: PDF, DOC, DOCX.
// Other types must not be sent via that endpoint — Zalo silently rejects.
func isZaloSupportedFileMIME(mime string) bool {
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "application/pdf",
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return true
	}
	return false
}

// isMIMEDenied reports whether mime is in the admin-configured deny list.
// Match is case-insensitive and exact (no glob/prefix). Empty list = allow all.
func isMIMEDenied(mime string, deny config.FlexibleStringSlice) bool {
	if len(deny) == 0 {
		return false
	}
	target := strings.ToLower(strings.TrimSpace(mime))
	if target == "" {
		return false
	}
	for _, d := range deny {
		if strings.EqualFold(strings.TrimSpace(d), target) {
			return true
		}
	}
	return false
}

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

// SendImage uploads an image and posts an attachment message. mime must
// be "image/jpeg" or "image/png" — used to pick the multipart filename
// extension which Zalo uses to validate the payload type.
func (c *Channel) SendImage(ctx context.Context, userID string, data []byte, mime string) (string, error) {
	tok, err := c.uploadImage(ctx, data, mime)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message": map[string]any{
			"attachment": map[string]any{
				"type":    "image",
				"payload": map[string]any{"attachment_id": tok},
			},
		},
	}
	mid, err := c.post(ctx, sendMessagePath, body)
	if err == nil {
		slog.Info("zalo_oauth.sent", "type", "image", "message_id", mid, "oa_id", c.creds.OAID)
	}
	return mid, err
}

// SendGIF uploads animated-GIF bytes to Zalo's dedicated gif endpoint
// and posts an image-attachment message referencing the upload token.
// Zalo caps /upload/gif at 5MB (callers should enforce before calling).
func (c *Channel) SendGIF(ctx context.Context, userID string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("zalo_oauth: refusing to send empty gif")
	}
	tok, err := c.uploadGIF(ctx, data)
	if err != nil {
		return "", err
	}
	// GIFs ride as type=image per Zalo's SDK convention; the upload
	// token is sufficient for the player to recognize animation.
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message": map[string]any{
			"attachment": map[string]any{
				"type":    "image",
				"payload": map[string]any{"attachment_id": tok},
			},
		},
	}
	mid, err := c.post(ctx, sendMessagePath, body)
	if err == nil {
		slog.Info("zalo_oauth.sent", "type", "gif", "message_id", mid, "oa_id", c.creds.OAID)
	}
	return mid, err
}

// SendFile uploads a file and posts an attachment message. filename is
// passed in the multipart "filename" field so Zalo preserves it for the
// recipient. Empty payloads and admin-blocked MIME types are rejected
// before the HTTP call.
func (c *Channel) SendFile(ctx context.Context, userID string, data []byte, filename, mime string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("zalo_oauth: refusing to send empty/zero-byte file %q", filename)
	}
	if isMIMEDenied(mime, c.cfg.FileDenyMIME) {
		return "", fmt.Errorf("zalo_oauth: file MIME %q denied by tenant policy", mime)
	}
	tok, err := c.uploadFile(ctx, data, filename)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"recipient": map[string]any{"user_id": userID},
		"message": map[string]any{
			"attachment": map[string]any{
				"type":    "file",
				"payload": map[string]any{"attachment_id": tok},
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
