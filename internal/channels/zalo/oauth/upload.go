package zalooauth

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const maxFilenameLen = 200 // Zalo's observed cap

// Upload endpoints live on /v2.0/* (empirically verified 2026-04-20
// against live Zalo OA — v3.0 variants return 404). The message-send
// endpoint /v3.0/oa/message/cs stays on v3.0.
const (
	uploadImagePath = "/v2.0/oa/upload/image"
	uploadFilePath  = "/v2.0/oa/upload/file"
	uploadGIFPath   = "/v2.0/oa/upload/gif"
)

// uploadImage uploads raw image bytes to Zalo and returns the upload `token`
// that subsequent send-attachment calls reference. Filename carries a real
// extension because Zalo's endpoint uses it to validate the payload type
// (live observation: filename without extension yields a 0-error but
// empty-data response).
func (c *Channel) uploadImage(ctx context.Context, data []byte, mime string) (string, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return "", err
	}
	filename := "image.jpg"
	if mime == "image/png" {
		filename = "image.png"
	}
	raw, err := c.client.apiPostMultipart(ctx, uploadImagePath, "file", filename, data, nil, tok)
	if err != nil {
		return "", err
	}
	return parseUploadToken(raw)
}

// uploadGIF uploads animated-GIF bytes to Zalo's dedicated gif endpoint
// (cap 5MB) and returns the upload token for the subsequent send call.
func (c *Channel) uploadGIF(ctx context.Context, data []byte) (string, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return "", err
	}
	raw, err := c.client.apiPostMultipart(ctx, uploadGIFPath, "file", "image.gif", data, nil, tok)
	if err != nil {
		return "", err
	}
	return parseUploadToken(raw)
}

// uploadFile uploads a file with its original filename and returns the
// upload token. filename is sent in the multipart "filename" field so Zalo
// preserves it for the recipient. Filename is sanitized — pathological
// inputs (path traversal, dot-only, empty, oversized) get a safe fallback.
func (c *Channel) uploadFile(ctx context.Context, data []byte, filename string) (string, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return "", err
	}
	safe := sanitizeFilename(filename)
	raw, err := c.client.apiPostMultipart(ctx, uploadFilePath, "file", safe,
		data, map[string]string{"filename": safe}, tok)
	if err != nil {
		return "", err
	}
	return parseUploadToken(raw)
}

// sanitizeFilename strips any path component, trims whitespace, replaces
// dot-only / empty names with a unique fallback, and caps length at 200.
// Unicode is preserved (Zalo accepts UTF-8 filenames).
func sanitizeFilename(raw string) string {
	name := filepath.Base(strings.TrimSpace(raw))
	switch name {
	case "", ".", "..", string(filepath.Separator):
		return fmt.Sprintf("file-%d.bin", time.Now().Unix())
	}
	if len(name) > maxFilenameLen {
		name = name[:maxFilenameLen]
	}
	return name
}

// parseUploadToken extracts the `token` field from the standard upload
// response envelope: {"error":0,"data":{"token":"..."}}
//
// If `data.token` is missing we include a redacted prefix of the raw
// response in the error so the next-time triage sees what Zalo actually
// returned instead of a generic "missing data.token". Raw bytes are
// truncated to 500 chars to avoid log spam on large payloads.
func parseUploadToken(raw json.RawMessage) (string, error) {
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("zalo_oauth: decode upload response: %w", err)
	}
	if env.Data.Token == "" {
		preview := string(raw)
		if len(preview) > 500 {
			preview = preview[:500] + "…(truncated)"
		}
		return "", fmt.Errorf("zalo_oauth: upload response missing data.token (raw=%s)", preview)
	}
	return env.Data.Token, nil
}
