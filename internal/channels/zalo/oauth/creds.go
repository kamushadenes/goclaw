// Package zalooauth implements the phone-number-tied Zalo Official Account
// channel using OAuth v4 (oauth.zaloapp.com + openapi.zalo.me). Distinct
// from internal/channels/zalo (Bot OA, static token) and zalo/personal
// (QR personal). Different auth, different host, different message shapes.
package zalooauth

import (
	"encoding/json"
	"time"
)

// ChannelCreds is the plaintext shape of the credentials JSON stored
// inside the channel_instances.credentials BLOB. The store layer encrypts
// the entire blob — do NOT call crypto.Encrypt/Decrypt on individual fields.
type ChannelCreds struct {
	AppID         string    `json:"app_id"`
	SecretKey     string    `json:"secret_key"`
	OAID          string    `json:"oa_id,omitempty"`
	AccessToken   string    `json:"access_token,omitempty"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	LastRefreshAt time.Time `json:"last_refresh_at,omitempty"`
}

// LoadCreds parses plaintext credential JSON. The store layer has already
// decrypted the surrounding blob.
func LoadCreds(raw json.RawMessage) (*ChannelCreds, error) {
	var c ChannelCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Marshal returns plaintext JSON. The store layer re-encrypts on Update.
func (c *ChannelCreds) Marshal() (json.RawMessage, error) {
	return json.Marshal(c)
}

// WithTokens copies new tokens onto the receiver and stamps LastRefreshAt.
// Caller must pass a non-nil tok — passing nil indicates a programming error
// upstream (refresh/exchange should never return (nil, nil)).
func (c *ChannelCreds) WithTokens(tok *Tokens) {
	c.AccessToken = tok.AccessToken
	c.RefreshToken = tok.RefreshToken
	c.ExpiresAt = tok.ExpiresAt
	c.LastRefreshAt = time.Now().UTC()
}
