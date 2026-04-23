package zalooauth

// Known Zalo OA error codes observed in production. Keep the value
// semantics exactly as Zalo returns them — do NOT renumber.
//
// The access-token-invalid family is returned with inconsistent signs and
// even different magnitudes across endpoints (216, -216, 401, -401 all
// observed for the same root cause). All four are treated identically.
const (
	// Access-token invalid/expired at OpenAPI layer. Triggers
	// ForceRefresh + one retry in Channel.post.
	codeAccessTokenInvalid216Neg = -216
	codeAccessTokenInvalid216Pos = 216
	codeAccessTokenInvalid401Neg = -401
	codeAccessTokenInvalid401Pos = 401

	// Refresh token dead — requires operator re-consent via paste-code flow.
	// Escalated to ErrAuthExpired by classifyRefreshError. Today detected
	// via substring match on the message ("invalid_grant") rather than
	// code comparison; documented here for future code-based routing.
	codeInvalidGrant = -118

	// Payload shape wrong. Observed when the send endpoint rejected the
	// simple {"type":"image","payload":{"attachment_id"}} shape and forced
	// the template/media shape. If seen again post-refactor, check send.go
	// against the wire-shape fixtures in send_fixture_test.go.
	codeParamsInvalid = -201

	// Upload body exceeds the endpoint cap (image 1MB, file 5MB, gif 5MB).
	// image_compress.go downshifts before calling; this code only surfaces
	// when downshift doesn't yield a small-enough payload.
	codeFileSizeExceeded = -210

	// OAuth consent layer — redirect_uri registered with Zalo console does
	// not match the one sent in the authorize URL. Surfaces during the
	// paste-code exchange before a channel ever establishes.
	codeInvalidRedirectURI = -14003
)

// isAccessTokenInvalid reports whether code belongs to the access-token
// invalid/expired family (216 / -216 / 401 / -401). Callers use this
// when deciding whether to ForceRefresh + retry.
func isAccessTokenInvalid(code int) bool {
	switch code {
	case codeAccessTokenInvalid216Neg, codeAccessTokenInvalid216Pos,
		codeAccessTokenInvalid401Neg, codeAccessTokenInvalid401Pos:
		return true
	}
	return false
}
