package zalooauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoint defaults — overridden in tests via Client.{apiBase,oauthBase}.
// API paths include their own version prefix (/v3.0/...) so apiBase is
// version-free and per-call paths stay self-documenting.
const (
	defaultOAuthBase = "https://oauth.zaloapp.com/v4"
	defaultAPIBase   = "https://openapi.zalo.me" // v2.0 is discontinued (per ChickenAI SDK); paths use /v3.0
)

// uploadTimeout is generous because multipart uploads of a few MB over a
// mobile carrier can take longer than the default 15s API timeout.
const uploadTimeout = 60 * time.Second

// Client wraps Zalo's OAuth + OpenAPI hosts.
type Client struct {
	http      *http.Client
	oauthBase string
	apiBase   string
}

// NewClient returns a Client with the given timeout.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		http:      &http.Client{Timeout: timeout},
		oauthBase: defaultOAuthBase,
		apiBase:   defaultAPIBase,
	}
}

// ErrRateLimit indicates Zalo returned HTTP 429. Callers should back off
// (the polling loop switches to a 30s ticker until a successful cycle).
var ErrRateLimit = errors.New("zalo_oauth: rate limited")

// APIError is returned when Zalo replies with a non-zero error envelope.
type APIError struct {
	Code    int    `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zalo api error %d: %s", e.Code, e.Message)
}

// isAuth reports whether this error indicates an invalid/expired access
// token at the OpenAPI layer (distinct from refresh-token death — that's
// classifyRefreshError's job). Codes from the Zalo OA SDK (UNVERIFIED
// official doc; mirrors the conservative substring fallback).
//
// 216 / -216 / 401 are the codes commonly seen for "access_token invalid".
// Substring fallback covers documentation drift.
func (e *APIError) isAuth() bool {
	if e == nil {
		return false
	}
	switch e.Code {
	case 216, -216, 401, -401:
		return true
	}
	msg := strings.ToLower(e.Message)
	return strings.Contains(msg, "access_token") && (strings.Contains(msg, "invalid") || strings.Contains(msg, "expired"))
}

// apiGet performs GET apiBase+path with extra query params merged. Token
// rides as `?access_token=...` (Zalo convention). Same envelope handling
// as apiPost: 4xx becomes APIError when body parses, otherwise raw http
// status. 429 is bubbled as ErrRateLimit so callers can switch into backoff.
func (c *Client) apiGet(ctx context.Context, path string, query url.Values, accessToken string) (json.RawMessage, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("zalo_oauth: empty access_token for %s", path)
	}
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("access_token", accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBase+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	return c.do(req, path)
}

// apiPost POSTs application/json to apiBase+path with the access token in
// the URL query param `?access_token=...` (Zalo convention, NOT a header).
// Surfaces both HTTP-status errors and Zalo's in-body error envelope.
//
// Logging note: only `path` is included in error messages — never the full
// URL (which contains the token).
func (c *Client) apiPost(ctx context.Context, path string, body any, accessToken string) (json.RawMessage, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	u, err := c.urlWithToken(path, accessToken)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, path)
}

// apiPostMultipart uploads a single file as multipart/form-data with the
// given form fields. Used by upload/image and upload/file endpoints.
func (c *Client) apiPostMultipart(ctx context.Context, path string, fileFieldName, fileName string, fileBytes []byte, fields map[string]string, accessToken string) (json.RawMessage, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return nil, fmt.Errorf("write field %s: %w", k, err)
		}
	}
	part, err := mw.CreateFormFile(fileFieldName, fileName)
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}
	if _, err := part.Write(fileBytes); err != nil {
		return nil, fmt.Errorf("write file part: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart: %w", err)
	}

	u, err := c.urlWithToken(path, accessToken)
	if err != nil {
		return nil, err
	}
	// Use a per-request client with the longer upload timeout instead of
	// mutating the shared client.
	uploadClient := &http.Client{Timeout: uploadTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return nil, fmt.Errorf("build upload request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return doRequest(uploadClient, req, path)
}

// urlWithToken builds the full URL with the access_token query param.
// Returns an error if accessToken is empty (refusing to call without auth).
func (c *Client) urlWithToken(path, accessToken string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("zalo_oauth: empty access_token for %s", path)
	}
	q := url.Values{"access_token": {accessToken}}
	return c.apiBase + path + "?" + q.Encode(), nil
}

// do runs req against the shared http client and parses the envelope.
func (c *Client) do(req *http.Request, path string) (json.RawMessage, error) {
	return doRequest(c.http, req, path)
}

// doRequest executes the HTTP call and parses Zalo's envelope. Path-only
// in error messages — never the full URL (token leakage).
//
// Token redaction: net/http wraps transport errors in *url.Error which
// embeds the request URL (with `?access_token=...`) in its Error() string.
// We rewrite urlErr.URL to a token-free form before bubbling the error up
// so any upstream consumer that prints the error chain doesn't leak.
func doRequest(client *http.Client, req *http.Request, path string) (json.RawMessage, error) {
	resp, err := client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			urlErr.URL = path // strip host + token for safe Error()
		}
		return nil, fmt.Errorf("zalo api %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w (path=%s)", ErrRateLimit, path)
	}
	if resp.StatusCode >= 400 {
		var env APIError
		if jerr := json.Unmarshal(raw, &env); jerr == nil && (env.Code != 0 || env.Message != "") {
			return nil, &env
		}
		return nil, fmt.Errorf("zalo api %s: http %d", path, resp.StatusCode)
	}
	var env APIError
	if jerr := json.Unmarshal(raw, &env); jerr == nil && env.Code != 0 {
		return nil, &env
	}
	return raw, nil
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
