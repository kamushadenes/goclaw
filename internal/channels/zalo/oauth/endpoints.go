package zalooauth

// Zalo endpoint surface. Version prefixes are load-bearing — Zalo mixes
// API versions across endpoint families and moving between them silently
// returns empty payloads or 404s.
//
//   openapi.zalo.me/v2.0/* — legacy read + upload paths.
//   openapi.zalo.me/v3.0/* — modern send path.
//   oauth.zaloapp.com/v4/* — OAuth authorization code + token exchange.
const (
	// Host bases. Callers join base + path; paths embed their own version.
	// OAuth base keeps /v4 on the base so token-call paths stay short.
	defaultAPIBase   = "https://openapi.zalo.me"
	defaultOAuthBase = "https://oauth.zaloapp.com/v4"

	// v3.0 — outbound send (customer-service message endpoint).
	pathSendMessage = "/v3.0/oa/message/cs"

	// v2.0 — inbound read. Empirically verified 2026-04-20: v3.0 variants
	// 404 for these paths.
	pathListRecentChat = "/v2.0/oa/listrecentchat"

	// v2.0 — upload family. Each endpoint has its own size cap enforced by
	// Zalo (image 1MB, file 5MB, gif 5MB). See image_compress.go + upload.go.
	pathUploadImage = "/v2.0/oa/upload/image"
	pathUploadFile  = "/v2.0/oa/upload/file"
	pathUploadGIF   = "/v2.0/oa/upload/gif"

	// v4 OAuth — path joined onto defaultOAuthBase, so the literal does not
	// repeat /v4. Used by access_token (exchange + refresh).
	pathOAuthAccessToken = "/oa/access_token"
)
