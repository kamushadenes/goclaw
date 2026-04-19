package zalooauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultOAuthBase is overridden by Client.oauthBase in tests.
const defaultOAuthBase = "https://oauth.zaloapp.com/v4"

// Client wraps Zalo's OAuth host. Phase 03 will add an apiBase field for openapi.zalo.me.
type Client struct {
	http      *http.Client
	oauthBase string
}

// NewClient returns a Client with the given timeout.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		http:      &http.Client{Timeout: timeout},
		oauthBase: defaultOAuthBase,
	}
}

// APIError is returned when Zalo replies with a non-zero error envelope.
type APIError struct {
	Code    int    `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zalo api error %d: %s", e.Code, e.Message)
}

// postForm POSTs application/x-www-form-urlencoded with optional headers,
// returns the raw decoded JSON body. HTTP-status errors and Zalo's in-body
// error envelope (`error != 0`) are both surfaced as errors.
func (c *Client) postForm(ctx context.Context, fullURL string, headers map[string]string, body url.Values) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Best-effort decode of envelope for context; otherwise return status.
		var env APIError
		if jerr := json.Unmarshal(raw, &env); jerr == nil && (env.Code != 0 || env.Message != "") {
			return nil, &env
		}
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}

	// Zalo returns HTTP 200 with `{"error":N,"message":"..."}` for app-level errors.
	var env APIError
	if jerr := json.Unmarshal(raw, &env); jerr == nil && env.Code != 0 {
		return nil, &env
	}
	return raw, nil
}
