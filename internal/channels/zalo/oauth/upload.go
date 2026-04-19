package zalooauth

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	uploadImagePath = "/v3.0/oa/upload/image"
	uploadFilePath  = "/v3.0/oa/upload/file"
)

// uploadImage uploads raw image bytes to Zalo and returns the upload `token`
// that subsequent send-attachment calls reference.
func (c *Channel) uploadImage(ctx context.Context, data []byte) (string, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return "", err
	}
	raw, err := c.client.apiPostMultipart(ctx, uploadImagePath, "file", "image", data, nil, tok)
	if err != nil {
		return "", err
	}
	return parseUploadToken(raw)
}

// uploadFile uploads a file with its original filename and returns the
// upload token. filename is sent in the multipart "filename" field so Zalo
// preserves it for the recipient.
func (c *Channel) uploadFile(ctx context.Context, data []byte, filename string) (string, error) {
	tok, err := c.tokens.Access(ctx)
	if err != nil {
		return "", err
	}
	base := filepath.Base(filename)
	raw, err := c.client.apiPostMultipart(ctx, uploadFilePath, "file", base,
		data, map[string]string{"filename": base}, tok)
	if err != nil {
		return "", err
	}
	return parseUploadToken(raw)
}

// parseUploadToken extracts the `token` field from the standard upload
// response envelope: {"error":0,"data":{"token":"..."}}
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
		return "", fmt.Errorf("zalo_oauth: upload response missing data.token")
	}
	return env.Data.Token, nil
}
