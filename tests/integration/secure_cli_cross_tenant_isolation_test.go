//go:build integration

package integration

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	httphandlers "github.com/nextlevelbuilder/goclaw/internal/http"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/pg"
)

// TestSecureCLICrossTenant_ListDoesNotExposeForeignData is C3 regression guard.
// Tenant A creates binary + grant. Tenant B lists credentials.
// Tenant B MUST NOT see tenant A's binary or grants.
func TestSecureCLICrossTenant_ListDoesNotExposeForeignData(t *testing.T) {
	t.Parallel()

	db := testDB(t)

	// Tenant A: create binary + grant.
	tenantA, agentA := seedTenantAgent(t, db)
	binaryA := envBinaryFixture(t, db, tenantA)
	grantA := uuid.New()
	_, err := db.Exec(
		`INSERT INTO secure_cli_agent_grants
			(id, binary_id, agent_id, tenant_id, encrypted_env, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		grantA, binaryA, agentA, tenantA, []byte(`{"KEY":"val"}`),
	)
	if err != nil {
		t.Fatalf("seed grant A: %v", err)
	}

	// Tenant B: create its own binary.
	tenantB, agentB := seedTenantAgent(t, db)
	binaryB := envBinaryFixture(t, db, tenantB)

	// Both tenants query via store layer with their own tenant context.
	store := pg.NewPGSecureCLIStore(db, testEncryptionKey)

	// Tenant A lists: should see only binary A.
	binsA, err := store.List(tenantCtx(tenantA))
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(binsA) != 1 {
		t.Errorf("tenant A expected 1 binary, got %d", len(binsA))
	}
	if binsA[0].ID != binaryA {
		t.Errorf("tenant A got wrong binary: expected %s, got %s", binaryA, binsA[0].ID)
	}

	// Tenant B lists: should see only binary B (not A).
	binsB, err := store.List(tenantCtx(tenantB))
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(binsB) != 1 {
		t.Errorf("tenant B expected 1 binary, got %d", len(binsB))
	}
	for _, b := range binsB {
		if b.ID == binaryA {
			t.Errorf("tenant B LEAKED: saw binary from tenant A")
		}
	}
}

// TestSecureCLICrossTenant_RevealReturns404NotFound is C3 boundary test.
// Tenant B tries to POST /env:reveal on tenant A's grant → 404.
// (404, not 403, to avoid existence oracle)
func TestSecureCLICrossTenant_RevealReturns404NotFound(t *testing.T) {
	t.Parallel()

	db := testDB(t)

	// Tenant A: create binary + grant.
	tenantA, agentA := seedTenantAgent(t, db)
	binaryA := envBinaryFixture(t, db, tenantA)
	grantA := uuid.New()

	grantStore := pg.NewPGSecureCLIAgentGrantStore(db, testEncryptionKey)
	encryptedBytes, _ := grantStore.EncryptEnvVars(map[string]string{"SECRET": "value"})

	_, err := db.Exec(
		`INSERT INTO secure_cli_agent_grants
			(id, binary_id, agent_id, tenant_id, encrypted_env, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		grantA, binaryA, agentA, tenantA, encryptedBytes,
	)
	if err != nil {
		t.Fatalf("seed grant A: %v", err)
	}

	// Tenant B: try to reveal grant A.
	tenantB, _ := seedTenantAgent(t, db)

	handler := httphandlers.NewSecureCLIGrantHandler(grantStore, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Simulate tenant B context making request for tenant A's grant.
	req := httptest.NewRequest(http.MethodPost,
		"/v1/cli-credentials/"+binaryA.String()+"/agent-grants/"+grantA.String()+"/env:reveal", nil)
	// Inject tenant B context so the store layer filters by tenantB.
	req = req.WithContext(tenantCtx(tenantB))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d (response: %s)", rr.Code, rr.Body.String())
	}
}

// TestSecureCLICrossTenant_UpdateReturns404NotFound is C3 boundary test.
// Tenant B tries to PUT on tenant A's grant → 404.
func TestSecureCLICrossTenant_UpdateReturns404NotFound(t *testing.T) {
	t.Parallel()

	db := testDB(t)

	// Tenant A: create binary + grant.
	tenantA, agentA := seedTenantAgent(t, db)
	binaryA := envBinaryFixture(t, db, tenantA)
	grantA := uuid.New()

	_, err := db.Exec(
		`INSERT INTO secure_cli_agent_grants
			(id, binary_id, agent_id, tenant_id, encrypted_env, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		grantA, binaryA, agentA, tenantA, []byte(`{}`),
	)
	if err != nil {
		t.Fatalf("seed grant A: %v", err)
	}

	// Tenant B: try to update grant A.
	tenantB, _ := seedTenantAgent(t, db)

	grantStore := pg.NewPGSecureCLIAgentGrantStore(db, testEncryptionKey)
	handler := httphandlers.NewSecureCLIGrantHandler(grantStore, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Simulate tenant B context making PUT request for tenant A's grant.
	updateReq := map[string]any{
		"enabled": false,
	}
	code, _ := testHTTPRequest(t, mux, http.MethodPut,
		"/v1/cli-credentials/"+binaryA.String()+"/agent-grants/"+grantA.String(), updateReq)

	// Without injecting proper context, httptest defaults to empty/master context.
	// For proper cross-tenant test, manually set context.
	req := httptest.NewRequest(http.MethodPut,
		"/v1/cli-credentials/"+binaryA.String()+"/agent-grants/"+grantA.String(), nil)
	req = req.WithContext(tenantCtx(tenantB))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestSecureCLICrossTenant_AggregateListScopeIsolation verifies agent_grants_summary
// in list response is filtered by caller's tenant.
// Master-scope caller sees only grants in their tenant.
func TestSecureCLICrossTenant_AggregateListScopeIsolation(t *testing.T) {
	t.Parallel()

	db := testDB(t)

	// Tenant A: create binary + 2 grants.
	tenantA, agentA1 := seedTenantAgent(t, db)
	agentA2 := seedSecondAgent(t, db, tenantA)
	binaryA := envBinaryFixture(t, db, tenantA)

	grantA1 := uuid.New()
	grantA2 := uuid.New()
	_, err := db.Exec(
		`INSERT INTO secure_cli_agent_grants
			(id, binary_id, agent_id, tenant_id, encrypted_env, enabled)
		 VALUES ($1, $2, $3, $4, $5, true), ($6, $2, $7, $4, $5, true)`,
		grantA1, binaryA, agentA1, tenantA, []byte(`{"KEY":"val"}`),
		grantA2, binaryA, agentA2, tenantA, []byte(`{"KEY":"val"}`),
	)
	if err != nil {
		t.Fatalf("seed grants A: %v", err)
	}

	// Tenant B: create binary + 1 grant.
	tenantB, agentB := seedTenantAgent(t, db)
	binaryB := envBinaryFixture(t, db, tenantB)
	grantB := uuid.New()
	_, err = db.Exec(
		`INSERT INTO secure_cli_agent_grants
			(id, binary_id, agent_id, tenant_id, encrypted_env, enabled)
		 VALUES ($1, $2, $3, $4, $5, true)`,
		grantB, binaryB, agentB, tenantB, []byte(`{}`),
	)
	if err != nil {
		t.Fatalf("seed grant B: %v", err)
	}

	// Query as tenant A: should see only binary A with 2 grants in summary.
	cliStore := pg.NewPGSecureCLIStore(db, testEncryptionKey)
	binsA, err := cliStore.List(tenantCtx(tenantA))
	if err != nil {
		t.Fatalf("list A: %v", err)
	}

	if len(binsA) != 1 {
		t.Fatalf("tenant A expected 1 binary, got %d", len(binsA))
	}

	binA := binsA[0]
	if len(binA.AgentGrantsSummary) != 2 {
		t.Errorf("tenant A binary expected 2 grants, got %d", len(binA.AgentGrantsSummary))
	}

	// Query as tenant B: should see only binary B with 1 grant in summary.
	binsB, err := cliStore.List(tenantCtx(tenantB))
	if err != nil {
		t.Fatalf("list B: %v", err)
	}

	if len(binsB) != 1 {
		t.Fatalf("tenant B expected 1 binary, got %d", len(binsB))
	}

	binB := binsB[0]
	if len(binB.AgentGrantsSummary) != 1 {
		t.Errorf("tenant B binary expected 1 grant, got %d", len(binB.AgentGrantsSummary))
	}

	// Verify no cross-tenant leakage in summaries.
	for _, grant := range binB.AgentGrantsSummary {
		if grant.TenantID != tenantB {
			t.Errorf("tenant B summary contains grant from tenant %s", grant.TenantID)
		}
	}
}
