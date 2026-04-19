package zalooauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Tokens is the parsed OAuth response.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// tokenResponse mirrors Zalo's OAuth v4 response body. Unknown fields
// are tolerated (forward-compat).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds, typically 3600
}

// ExchangeCode swaps an authorization code for an (access, refresh) token pair.
// POST oauth.zaloapp.com/v4/oa/access_token, secret_key in HEADER (not body).
func (c *Client) ExchangeCode(ctx context.Context, appID, secretKey, code string) (*Tokens, error) {
	form := url.Values{
		"app_id":     {appID},
		"code":       {code},
		"grant_type": {"authorization_code"},
	}
	return c.tokenCall(ctx, secretKey, form)
}

// RefreshToken trades a refresh token for a new (access, refresh) pair.
// Refresh tokens are SINGLE-USE — every successful refresh rotates both.
func (c *Client) RefreshToken(ctx context.Context, appID, secretKey, refresh string) (*Tokens, error) {
	form := url.Values{
		"app_id":        {appID},
		"refresh_token": {refresh},
		"grant_type":    {"refresh_token"},
	}
	return c.tokenCall(ctx, secretKey, form)
}

func (c *Client) tokenCall(ctx context.Context, secretKey string, form url.Values) (*Tokens, error) {
	headers := map[string]string{"secret_key": secretKey}
	raw, err := c.postForm(ctx, c.oauthBase+"/oa/access_token", headers, form)
	if err != nil {
		return nil, err
	}
	var resp tokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("zalo oauth: empty access_token in response")
	}
	exp := time.Now().UTC().Add(time.Duration(resp.ExpiresIn) * time.Second)
	return &Tokens{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    exp,
	}, nil
}

// ConsentURL builds the redirect URL the operator visits to authorize the OA.
// Returned URL embeds the supplied state token for CSRF protection (validated
// in the WS exchange_code handler).
func ConsentURL(appID, redirectURI, state string) string {
	q := url.Values{
		"app_id":       {appID},
		"redirect_uri": {redirectURI},
		"state":        {state},
	}
	return defaultOAuthBase + "/oa/permission?" + q.Encode()
}
