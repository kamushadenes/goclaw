//go:build integration

package integration

// secure_cli_list_shape_freeze_test.go — C4 characterization test (Phase 1a).
//
// Freezes the JSON shape returned by GET /v1/cli-credentials so that
// Phase 2-4 store and handler changes cannot silently break the list contract.
//
// Design notes:
//   - Uses httptest.NewRecorder (no real network) against the real PG store.
//   - No gateway token configured (pkgGatewayToken == "") → auth middleware
//     auto-grants RoleAdmin in dev/test mode. See internal/http/auth.go:resolveAuthWithBearer.
//   - Seeds one binary per test to have a predictable non-empty response,
//     then asserts mandatory top-level keys and item field names.
//   - Does NOT assert exact values (UUIDs, timestamps) — only key presence and types.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	httphandlers "github.com/nextlevelbuilder/goclaw/internal/http"
	"github.com/nextlevelbuilder/goclaw/internal/store/pg"
)

// listShapeFixture seeds a minimal CLI binary and returns its ID.
// Cleanup removes the binary (and cascades to grants + user-creds).
func listShapeFixture(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	binaryID := uuid.New()
	_, err := db.Exec(
		`INSERT INTO secure_cli_binaries
			(id, tenant_id, binary_name, encrypted_env, description, enabled, is_global)
		 VALUES ($1, $2, $3, $4, 'shape-freeze test binary', true, true)`,
		binaryID, tenantID, "shapefreeze_"+binaryID.String()[:8], []byte(`{"SHAPE_KEY":"v"}`),
	)
	if err != nil {
		t.Fatalf("listShapeFixture seed binary: %v", err)
	}
	t.Cleanup(func() {
		db.Exec("DELETE FROM secure_cli_agent_grants WHERE binary_id = $1", binaryID)
		db.Exec("DELETE FROM secure_cli_user_credentials WHERE binary_id = $1", binaryID)
		db.Exec("DELETE FROM secure_cli_binaries WHERE id = $1", binaryID)
	})
	return binaryID
}

// TestSecureCLIList_ResponseShapeFreeze is the C4 characterization test.
//
// It freezes the current JSON contract of GET /v1/cli-credentials:
//
//	{ "items": [ { <mandatory fields> } ] }
//
// Any Phase 2-8 change that drops or renames a top-level key or item field
// will cause this test to fail — a deliberate regression guard.
func TestSecureCLIList_ResponseShapeFreeze(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	tenantID, _ := seedTenantAgent(t, db)
	listShapeFixture(t, db, tenantID)

	// Wire the handler against the real PG store.
	cliStore := pg.NewPGSecureCLIStore(db, testEncryptionKey)
	handler := httphandlers.NewSecureCLIHandler(cliStore, nil /* no bus needed */)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/cli-credentials", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Decode top-level envelope.
	var envelope map[string]json.RawMessage
	if err := json.NewDecoder(rr.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// ── Top-level shape ──────────────────────────────────────────────────────
	// Must have exactly "items" key. If a new Phase adds "meta" or similar, this
	// guard ensures a deliberate decision rather than silent addition.
	if _, ok := envelope["items"]; !ok {
		t.Errorf("response missing top-level key 'items'; got keys: %v", mapKeys(envelope))
	}
	if len(envelope) != 1 {
		t.Errorf("response has extra top-level keys (want only 'items'): %v", mapKeys(envelope))
	}

	// ── Item shape ───────────────────────────────────────────────────────────
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["items"], &items); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("items array is empty — fixture seeding failed")
	}

	// Mandatory fields that MUST be present on every item.
	// Derived from store.SecureCLIBinary JSON tags + handler logic.
	// Shape evolution (Phase 4): added "agent_grants_summary" — additive field,
	// always present as [] even when no grants exist.
	mandatoryFields := []string{
		"id",
		"binary_name",
		"description",
		"deny_args",
		"deny_verbose",
		"timeout_seconds",
		"tips",
		"is_global",
		"enabled",
		"created_by",
		"agent_grants_summary", // Phase 4: per-binary grant summary (env_set bool only, never blob)
	}

	// Fields that MUST be absent (security: never expose raw credential data).
	forbiddenFields := []string{
		"encrypted_env", // raw bytes — must never appear in list response
	}

	item := items[0]
	for _, field := range mandatoryFields {
		if _, ok := item[field]; !ok {
			t.Errorf("item missing mandatory field %q; present fields: %v", field, mapKeys(item))
		}
	}
	for _, field := range forbiddenFields {
		if _, ok := item[field]; ok {
			t.Errorf("item contains forbidden field %q (credential leak)", field)
		}
	}

	// env_keys is conditionally present (omitempty when empty).
	// Just verify it is NOT the raw encrypted blob when present.
	if raw, ok := item["env_keys"]; ok {
		// Must be a JSON array, not a binary blob.
		var keys []string
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Errorf("env_keys is not a JSON array of strings: %v (raw: %s)", err, raw)
		}
		// Must contain "SHAPE_KEY" since we seeded with {"SHAPE_KEY":"v"}.
		found := false
		for _, k := range keys {
			if k == "SHAPE_KEY" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("env_keys should contain 'SHAPE_KEY' for the seeded binary; got: %v", keys)
		}
	}
}

// mapKeys returns sorted key names from a map for diagnostic messages.
func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
